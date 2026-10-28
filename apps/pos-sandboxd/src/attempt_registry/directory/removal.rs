//! Exact unmounted directory removal, retaining durable intent for recovery.

use rustix::fs::{unlinkat, AtFlags, Dir};

use super::{registry_io, File, PreparedAttemptDirectory, SystemdAttemptRegistryError};

type RemovalResult = Result<(), SystemdAttemptRegistryError>;

impl PreparedAttemptDirectory {
    /// Remove this attempt's empty, unmounted root and attempt directories.
    ///
    /// The exact durable record, held directory identities, private ancestors,
    /// no-mount/no-symlink paths and empty root are checked before any removal.
    /// Unexpected attempt children also reject before the root is removed.
    /// Each removal uses its held parent descriptor and synchronizes that parent.
    /// Consuming this value closes its directory descriptors on return.
    ///
    /// The lifecycle controller must exclusively own the private tree and finish
    /// unit/process shutdown and root unmounting before calling. This operation
    /// does not establish unit, cgroup, device or namespace absence. The durable
    /// intent is retained, including after successful directory removal; only
    /// complete lifecycle reconciliation may delete it or reopen admission.
    /// A previously quarantined owner can remove verified directories, but this
    /// never clears its quarantine.
    ///
    /// # Errors
    /// Rejects an unsafe or changed record/tree, mounts, unexpected contents,
    /// poisoned ownership, or any removal/fsync failure. Failure may leave either
    /// directory already removed. New commits remain closed and recovery must
    /// inspect the retained intent and surviving directory identities.
    pub fn remove_unmounted(self) -> RemovalResult {
        let mut state = match self.planned.state.lock() {
            Ok(state) => state,
            Err(_) => return Err(SystemdAttemptRegistryError::ReconciliationRequired),
        };
        let result = self
            .verify_record_and_tree()
            .and_then(|()| require_only_root(&self.attempt))
            .and_then(|()| remove_empty(&self.attempt, "root"))
            .and_then(|()| {
                remove_empty(
                    &self.attempts,
                    self.intent().unit_name().attempt_component(),
                )
            });
        state.failed |= result.is_err();
        result
    }
}

fn require_only_root(directory: &File) -> RemovalResult {
    registry_io(|| Dir::read_from(directory).map_err(std::io::Error::from))
        .map_err(Into::into)
        .and_then(|entries| {
            for entry in entries {
                let entry = registry_io(|| entry.map_err(std::io::Error::from))
                    .map_err(SystemdAttemptRegistryError::from);
                match entry {
                    Ok(entry) => {
                        let name = entry.file_name().to_bytes();
                        if name != b"." && name != b".." && name != b"root" {
                            return Err(SystemdAttemptRegistryError::UnsafeRegistry);
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })
}

fn remove_empty(parent: &File, component: &str) -> RemovalResult {
    registry_io(|| unlinkat(parent, component, AtFlags::REMOVEDIR).map_err(std::io::Error::from))
        .and_then(|()| registry_io(|| parent.sync_all()))
        .map_err(Into::into)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    use super::super::super::tests::{in_lock_test_process, with_io_fault};
    use super::super::super::RegistryDirectory;
    use super::super::tests::{fixture, intent};
    use super::*;
    use crate::SystemdAttemptRecovery;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn eight_removals_preserve_exact_intents_and_leave_other_attempts_owned() -> TestResult {
        let (runtime, registry) = fixture()?;
        let mut prepared = Vec::new();
        for id in 1..=8 {
            prepared.push(registry.commit_planned(&intent(id)?)?.prepare_directory()?);
        }
        for (id, directory) in (1..=8).zip(prepared) {
            let planned = intent(id)?;
            let key = planned.unit_name().attempt_component();
            let record = runtime.path().join("registry").join(key);
            let bytes = fs::read(&record)?;
            directory.remove_unmounted()?;
            assert!(!runtime.path().join("attempts").join(key).exists());
            assert_eq!(fs::read(&record)?, bytes);
            assert_eq!(
                fs::read_dir(runtime.path().join("attempts"))?.count(),
                8 - usize::from(id)
            );
            assert_eq!(fs::read_dir(runtime.path().join("registry"))?.count(), 8);
        }
        // Directory removal neither deletes intents nor quarantines a clean owner.
        registry.commit_planned(&intent(9)?)?;
        Ok(())
    }

    #[test]
    fn contradictions_refuse_all_removal_and_close_new_commits() -> TestResult {
        for fault in 0..10 {
            let (runtime, registry) = fixture()?;
            let planned = intent(1)?;
            let key = planned.unit_name().attempt_component();
            let directory = registry.commit_planned(&planned)?.prepare_directory()?;
            let attempts = runtime.path().join("attempts");
            let attempt = attempts.join(key);
            let root = attempt.join("root");
            let record = runtime.path().join("registry").join(key);
            match fault {
                0 => fs::write(&record, b"changed")?,
                1 => fs::write(root.join("unexpected"), b"retained")?,
                2 => fs::write(attempt.join("unexpected"), b"retained")?,
                3 => fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?,
                4 => {
                    fs::rename(&root, attempt.join("held-root"))?;
                    fs::create_dir(&root)?;
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
                }
                5 => {
                    fs::rename(&attempt, attempts.join("held-attempt"))?;
                    std::os::unix::fs::symlink(attempts.join("held-attempt"), &attempt)?;
                }
                6 => {
                    fs::rename(&attempts, runtime.path().join("held-attempts"))?;
                    fs::create_dir(&attempts)?;
                    fs::set_permissions(&attempts, fs::Permissions::from_mode(0o700))?;
                }
                7 => fs::set_permissions(&attempts, fs::Permissions::from_mode(0o755))?,
                8 => fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o755))?,
                _ => {
                    let mut bytes = fs::read(&record)?;
                    bytes[52] ^= 1;
                    fs::write(&record, bytes)?;
                }
            }
            let record_before = fs::read(&record)?;
            let held_root = directory.root.try_clone()?;
            let held_attempt = directory.attempt.try_clone()?;
            assert!(directory.remove_unmounted().is_err(), "fault {fault}");
            assert!(held_root.metadata()?.nlink() > 0, "fault {fault}");
            assert!(held_attempt.metadata()?.nlink() > 0, "fault {fault}");
            assert_eq!(fs::read(&record)?, record_before);
            assert!(registry.commit_planned(&intent(2)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn every_removal_io_failure_retains_intent_and_recoverable_directory_state() -> TestResult {
        if !in_lock_test_process("attempt_registry::directory::removal::tests::every_removal_io_failure_retains_intent_and_recoverable_directory_state")? {
            return Ok(());
        }
        let operation_count = {
            let (_runtime, registry) = fixture()?;
            let prepared = registry.commit_planned(&intent(1)?)?.prepare_directory()?;
            let (result, count) = with_io_fault(None, || prepared.remove_unmounted());
            result?;
            count
        };
        let mut frontiers = [false; 3];
        for fail_at in 0..operation_count {
            let (runtime, registry) = fixture()?;
            let planned = intent(1)?;
            let key = planned.unit_name().attempt_component();
            let directory = registry.commit_planned(&planned)?.prepare_directory()?;
            let attempt = runtime.path().join("attempts").join(key);
            let root = attempt.join("root");
            let record = runtime.path().join("registry").join(key);
            let bytes = fs::read(&record)?;
            let attempt_metadata = fs::metadata(&attempt)?;
            let (result, count) = with_io_fault(Some(fail_at), || directory.remove_unmounted());
            assert!(
                matches!(result, Err(SystemdAttemptRegistryError::Io(_))),
                "boundary {fail_at}: {result:?}"
            );
            assert_eq!(count, fail_at + 1);
            assert_eq!(fs::read(&record)?, bytes);
            assert!(registry.commit_planned(&intent(2)?).is_err());
            let frontier = if root.exists() {
                0
            } else if attempt.exists() {
                1
            } else {
                2
            };
            frontiers[frontier] = true;
            drop(registry);
            let parent = File::open(runtime.path())?;
            let held =
                RegistryDirectory::from_runtime_directory(&parent, parent.metadata()?.uid())?;
            let recovery = SystemdAttemptRecovery::from_directory(held)?;
            let inventory = recovery.inventory_unmounted_directories()?;
            inventory.verify_unchanged()?;
            assert_eq!(inventory.directories().len(), usize::from(frontier != 2));
            if let Some(survivor) = inventory.directories().first() {
                assert_eq!(survivor.intent(), &planned);
                assert!(survivor.identity_was_committed());
                assert_eq!(
                    survivor.attempt_identity(),
                    (attempt_metadata.dev(), attempt_metadata.ino())
                );
                assert_eq!(survivor.root_identity().is_some(), frontier == 0);
            }
            assert_eq!(fs::read(record)?, bytes);
        }
        assert_eq!(frontiers, [true; 3]);
        Ok(())
    }

    #[test]
    fn quarantine_is_preserved_and_poisoned_ownership_never_removes() -> TestResult {
        for poisoned in [false, true] {
            let (runtime, registry) = fixture()?;
            let planned = intent(1)?;
            let directory = registry.commit_planned(&planned)?.prepare_directory()?;
            if poisoned {
                assert!(std::panic::catch_unwind(|| {
                    let _guard = registry.state.lock();
                    std::panic::resume_unwind(Box::new(()));
                })
                .is_err());
            } else {
                registry
                    .state
                    .lock()
                    .map_err(|_| "poisoned fixture")?
                    .failed = true;
            }
            let result = directory.remove_unmounted();
            assert_eq!(result.is_err(), poisoned);
            assert_eq!(
                runtime
                    .path()
                    .join("attempts")
                    .join(planned.unit_name().attempt_component())
                    .exists(),
                poisoned
            );
            assert!(registry.commit_planned(&intent(2)?).is_err());
        }
        Ok(())
    }
}
