//! Correlation of registry claims with held, unmounted attempt directories.

use rustix::fs::{openat2, Mode};

use super::super::{open_directory, remove_empty, require_empty};
use super::{
    registry_io, validate_directory, Dir, File, MetadataExt, PlannedAttemptIntent,
    RecoveredAttemptIntent, RegistryResult, ResolveFlags, SystemdAttemptRecovery,
    SystemdAttemptRegistryError,
};
use crate::RecordedRootEntry;

#[derive(Debug, Eq, PartialEq)]
struct DirectoryObservation {
    intent: RecoveredAttemptIntent,
    attempt: (u64, u64),
    root: Option<(u64, u64)>,
}

/// One existing unmounted directory correlated with its committed intent.
///
/// Private held descriptors prevent inode reuse from disguising substitution.
/// This observation does not establish unit, cgroup, loop or dm absence and
/// grants no deletion, activation, or admission-reopening authority.
#[derive(Debug)]
pub struct RecoveredUnmountedDirectory {
    attempt: File,
    _root: Option<File>,
    observation: DirectoryObservation,
}

impl RecoveredUnmountedDirectory {
    /// The exact committed planned identities for this directory.
    #[must_use]
    pub const fn intent(&self) -> &PlannedAttemptIntent {
        &self.observation.intent.planned
    }

    /// Observed `(device, inode)` of the held attempt directory.
    #[must_use]
    pub const fn attempt_identity(&self) -> (u64, u64) {
        self.observation.attempt
    }

    /// Observed root identity, absent before creation or after root removal.
    #[must_use]
    pub const fn root_identity(&self) -> Option<(u64, u64)> {
        self.observation.root
    }

    /// Whether the committed record already bound both directory identities.
    #[must_use]
    pub const fn identity_was_committed(&self) -> bool {
        self.observation.intent.directory_identities.is_some()
    }
}

/// Held inventory of the pre-activation directory tree under one recovery lock.
///
/// Mount crossings are rejected. Mounted recovery must use independent mount,
/// image and device correlation before any cleanup; this type cannot claim it.
#[derive(Debug)]
pub struct UnmountedDirectoryInventory<'a> {
    recovery: &'a SystemdAttemptRecovery,
    parent: File,
    directories: Vec<RecoveredUnmountedDirectory>,
}

impl SystemdAttemptRecovery {
    /// Correlate every existing unmounted attempt directory with a committed key.
    ///
    /// Accepts the post-mkdir/pre-identity-extension crash state only beneath
    /// held private runtime descriptors. Unknown directories, temporary-only
    /// ownership and recorded identity contradictions fail closed. Missing
    /// directories are observations of absence, not complete cleanup evidence.
    ///
    /// # Errors
    /// Rejects changed registry state, unsafe metadata, symlinks, mount crossings,
    /// nonempty roots, unexpected children, missing committed intent or identity
    /// mismatch. No filesystem resource is removed on success or failure.
    pub fn inventory_unmounted_directories(
        &self,
    ) -> RegistryResult<UnmountedDirectoryInventory<'_>> {
        self.verify_unchanged()?;
        let parent = open_attempts(self)?;
        let directories = inventory(self, &parent)?;
        let inventory = UnmountedDirectoryInventory {
            recovery: self,
            parent,
            directories,
        };
        inventory.verify_unchanged()?;
        Ok(inventory)
    }
}

impl UnmountedDirectoryInventory<'_> {
    /// Existing directories in canonical `AttemptId` component order.
    #[must_use]
    pub fn directories(&self) -> &[RecoveredUnmountedDirectory] {
        &self.directories
    }

    /// Recheck registry, parent identity, directory names and held identities.
    ///
    /// # Errors
    /// Rejects any contradiction, unsafe metadata, new mount, changed root
    /// contents or I/O failure. The registry lock remains held by recovery.
    pub fn verify_unchanged(&self) -> RegistryResult<()> {
        self.recovery.verify_unchanged()?;
        let parent = open_attempts(self.recovery)?;
        if identity(&parent)? != identity(&self.parent)? {
            return Err(SystemdAttemptRegistryError::UnsafeRegistry);
        }
        let current = inventory(self.recovery, &parent)?;
        if !current
            .iter()
            .map(|entry| &entry.observation)
            .eq(self.directories.iter().map(|entry| &entry.observation))
        {
            return Err(SystemdAttemptRegistryError::ReconciliationRequired);
        }
        self.recovery.verify_unchanged()
    }
}

impl UnmountedDirectoryInventory<'_> {
    /// Remove each held root, then its attempt directory, synchronizing the
    /// held parent after every removal. The caller proved the attempts clean.
    pub(super) fn remove_directories(&self) -> RegistryResult<()> {
        self.directories.iter().try_for_each(|directory| {
            let component = directory.intent().unit_name().attempt_component();
            directory
                .observation
                .root
                .map_or(Ok(()), |_| remove_empty(&directory.attempt, "root"))
                .and_then(|()| remove_empty(&self.parent, component))
        })
    }
}

impl SystemdAttemptRecovery {
    /// The existing root entry of every attempt directory whose identities a
    /// committed intent recorded, in canonical order.
    ///
    /// A mount is attached only after the directory identities were recorded,
    /// so no other attempt can carry one. Unknown directories are left to the
    /// directory inventory, which refuses them.
    ///
    /// # Errors
    /// Rejects changed registry state, unsafe metadata, a changed attempt
    /// directory identity, unexpected children and a root that is a symlink.
    pub(crate) fn recorded_root_entries(&self) -> RegistryResult<Vec<RecordedRootEntry>> {
        self.verify_unchanged()
            .and_then(|()| open_attempts(self))
            .and_then(|parent| names(&parent).map(|present| (parent, present)))
            .and_then(|(parent, present)| {
                self.entries
                    .iter()
                    .filter(|entry| {
                        !entry.is_temporary()
                            && present.iter().any(|name| name == entry.component())
                    })
                    .filter_map(super::RegistryRecoveryEntry::intent)
                    .filter_map(|intent| {
                        intent
                            .directory_identities
                            .map(|recorded| (intent, recorded[0]))
                    })
                    .map(|(intent, recorded)| {
                        root_entry(&parent, intent, recorded, self.directory.owner)
                    })
                    .filter_map(Result::transpose)
                    .collect()
            })
    }
}

/// The root entry of one recorded attempt directory, if it has one.
fn root_entry(
    parent: &File,
    intent: &RecoveredAttemptIntent,
    recorded: (u64, u64),
    owner: u32,
) -> RegistryResult<Option<RecordedRootEntry>> {
    open_directory(
        parent,
        intent.planned.unit_name().attempt_component(),
        ResolveFlags::NO_XDEV,
    )
    .and_then(|attempt| validate_directory(&attempt, owner, true).map(|()| attempt))
    .and_then(|attempt| identity(&attempt).map(|observed| (attempt, observed)))
    .and_then(|(attempt, observed)| {
        (observed == recorded)
            .then_some(attempt)
            .ok_or(SystemdAttemptRegistryError::UnsafeRegistry)
    })
    .and_then(|attempt| names(&attempt).map(|children| (attempt, children)))
    .and_then(|(attempt, children)| {
        match children.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            [] => Ok(None),
            ["root"] => openat2(
                &attempt,
                "root",
                crate::ATTEMPT_ROOT_OPEN,
                Mode::empty(),
                crate::ATTEMPT_ROOT_RESOLVE,
            )
            .map_err(|_| SystemdAttemptRegistryError::UnsafeRegistry)
            .map(|root| {
                Some(RecordedRootEntry {
                    intent: intent.clone(),
                    attempt,
                    root,
                })
            }),
            _ => Err(SystemdAttemptRegistryError::UnsafeRegistry),
        }
    })
}

fn open_attempts(recovery: &SystemdAttemptRecovery) -> RegistryResult<File> {
    let directory = &recovery.directory;
    validate_directory(&directory.runtime, directory.owner, true)?;
    let parent = open_directory(&directory.runtime, "attempts", ResolveFlags::NO_XDEV)?;
    validate_directory(&parent, directory.owner, true)?;
    Ok(parent)
}

fn inventory(
    recovery: &SystemdAttemptRecovery,
    parent: &File,
) -> RegistryResult<Vec<RecoveredUnmountedDirectory>> {
    names(parent)?
        .into_iter()
        .map(|name| {
            let intent = recovery
                .entries
                .iter()
                .find(|entry| !entry.is_temporary() && entry.component() == name)
                .and_then(super::RegistryRecoveryEntry::intent)
                .ok_or(SystemdAttemptRegistryError::InvalidIntent)?;
            read_directory(parent, &name, intent, recovery.directory.owner)
        })
        .collect()
}

fn read_directory(
    parent: &File,
    name: &str,
    intent: &RecoveredAttemptIntent,
    owner: u32,
) -> RegistryResult<RecoveredUnmountedDirectory> {
    let attempt = open_directory(parent, name, ResolveFlags::NO_XDEV)?;
    validate_directory(&attempt, owner, true)?;
    let root = match names(&attempt)?.as_slice() {
        [] => None,
        [name] if name == "root" => {
            let root = open_directory(&attempt, "root", ResolveFlags::NO_XDEV)?;
            validate_directory(&root, owner, true)?;
            require_empty(&root)?;
            Some(root)
        }
        _ => return Err(SystemdAttemptRegistryError::UnsafeRegistry),
    };
    let observed = DirectoryObservation {
        intent: intent.clone(),
        attempt: identity(&attempt)?,
        root: root.as_ref().map(identity).transpose()?,
    };
    if intent.directory_identities.is_some_and(|expected| {
        // A missing root also occurs between the two directory removals.
        // Every root that is still present must retain its committed identity.
        expected[0] != observed.attempt || observed.root.unwrap_or(expected[1]) != expected[1]
    }) {
        return Err(SystemdAttemptRegistryError::UnsafeRegistry);
    }
    Ok(RecoveredUnmountedDirectory {
        attempt,
        _root: root,
        observation: observed,
    })
}

fn identity(file: &File) -> RegistryResult<(u64, u64)> {
    registry_io(|| file.metadata())
        .map(|metadata| (metadata.dev(), metadata.ino()))
        .map_err(Into::into)
}

fn names(directory: &File) -> RegistryResult<Vec<String>> {
    let mut names = Vec::new();
    for entry in registry_io(|| Dir::read_from(directory).map_err(std::io::Error::from))? {
        let entry = registry_io(|| entry.map_err(std::io::Error::from))?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| SystemdAttemptRegistryError::UnsafeRegistry)?;
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
    }
    names.sort_unstable();
    Ok(names)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::super::tests::{in_lock_test_process, with_io_fault};
    use super::*;
    use crate::{SystemdAttemptRegistry, TransientServiceUnitName};
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, PermissionsExt};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn private_directory(path: &std::path::Path) -> TestResult {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn key(id: u8) -> TestResult<String> {
        Ok(TransientServiceUnitName::from_attempt_id([id; 16])?
            .attempt_component()
            .to_owned())
    }

    fn seed(runtime: &std::path::Path, registry: &SystemdAttemptRegistry) -> TestResult {
        for id in 1..=8 {
            let committed =
                registry.commit_planned(&PlannedAttemptIntent::new([id; 16], [2; 32])?)?;
            let attempt = runtime.join("attempts").join(key(id)?);
            match id {
                1 => (),
                2 => private_directory(&attempt)?,
                3 => {
                    private_directory(&attempt)?;
                    private_directory(&attempt.join("root"))?;
                }
                _ => {
                    committed.prepare_fixture_directory()?;
                }
            }
        }
        Ok(())
    }

    fn fixture() -> TestResult<(tempfile::TempDir, SystemdAttemptRecovery)> {
        let (directory, runtime, owner) = super::super::super::tests::fixture()?;
        private_directory(&directory.path().join("attempts"))?;
        let registry = SystemdAttemptRegistry::from_runtime_directory(&runtime, owner)?;
        seed(directory.path(), &registry)?;
        drop(registry);
        let held = super::super::RegistryDirectory::from_runtime_directory(&runtime, owner)?;
        Ok((directory, SystemdAttemptRecovery::from_directory(held)?))
    }

    #[test]
    fn public_recovery_correlates_eight_attempts_and_both_mkdir_crash_gaps() -> TestResult {
        if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_none() {
            let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/run-isolated-test.sh");
            let output = std::process::Command::new(runner).arg(std::env::current_exe()?)
                .arg("attempt_registry::recovery::directories::tests::public_recovery_correlates_eight_attempts_and_both_mkdir_crash_gaps").output()?;
            assert!(
                output.status.success(),
                "isolated directory inventory failed: {:?}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }
        let runtime = std::path::Path::new("/run/pigloros/sandbox");
        for path in [
            "/run/pigloros",
            "/run/pigloros/sandbox",
            "/run/pigloros/sandbox/registry",
            "/run/pigloros/sandbox/attempts",
        ] {
            private_directory(std::path::Path::new(path))?;
        }
        let registry = SystemdAttemptRegistry::open()?;
        seed(runtime, &registry)?;
        drop(registry);
        let recovery = SystemdAttemptRecovery::open()?;
        let inventory = recovery.inventory_unmounted_directories()?;
        assert_eq!(inventory.directories().len(), 7);
        for (id, entry) in (2..=8).zip(inventory.directories()) {
            assert_eq!(entry.intent().attempt_id(), [id; 16]);
            assert_eq!(entry.intent().sim1_digest(), [2; 32]);
            assert_eq!(entry.identity_was_committed(), id >= 4);
            let path = runtime.join("attempts").join(key(id)?);
            let metadata = fs::metadata(&path)?;
            assert_eq!(entry.attempt_identity(), (metadata.dev(), metadata.ino()));
            if id == 2 {
                assert_eq!(entry.root_identity(), None);
            } else {
                let metadata = fs::metadata(path.join("root"))?;
                assert_eq!(
                    entry.root_identity(),
                    Some((metadata.dev(), metadata.ino()))
                );
            }
        }
        inventory.verify_unchanged()?;
        drop(inventory);
        assert_eq!(fs::read_dir(runtime.join("registry"))?.count(), 9);
        assert_eq!(fs::read_dir(runtime.join("attempts"))?.count(), 7);
        assert!(SystemdAttemptRegistry::open().is_err());
        Ok(())
    }

    #[test]
    fn rejects_unknown_unsafe_and_contradictory_directory_state() -> TestResult {
        if !in_lock_test_process("attempt_registry::recovery::directories::tests::rejects_unknown_unsafe_and_contradictory_directory_state")? {
            return Ok(());
        }
        for fault in 0..11 {
            let (directory, recovery) = fixture()?;
            let attempts = directory.path().join("attempts");
            let attempt = attempts.join(key(4)?);
            let root = attempt.join("root");
            match fault {
                0 => private_directory(&attempts.join(key(9)?))?,
                1 => fs::write(attempt.join("unexpected"), b"not root")?,
                2 => fs::write(root.join("unexpected"), b"not empty")?,
                3 => fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?,
                4 => {
                    fs::remove_dir(&root)?;
                    fs::write(&root, b"not a directory")?;
                }
                5 => {
                    fs::rename(&root, directory.path().join("held-root"))?;
                    private_directory(&root)?;
                }
                6 => {
                    fs::rename(&attempt, directory.path().join("held-attempt"))?;
                    symlink(directory.path().join("held-attempt"), &attempt)?;
                }
                7 => fs::set_permissions(&attempts, fs::Permissions::from_mode(0o755))?,
                8 => private_directory(&attempts.join(std::ffi::OsString::from_vec(vec![0xff])))?,
                9 => {
                    fs::rename(&attempt, directory.path().join("held-attempt"))?;
                    private_directory(&attempt)?;
                    private_directory(&root)?;
                }
                _ => fs::write(attempts.join("not-a-directory"), b"unexpected")?,
            }
            assert!(recovery.inventory_unmounted_directories().is_err());
            assert_eq!(fs::read_dir(directory.path().join("registry"))?.count(), 9);
        }
        Ok(())
    }

    #[test]
    fn partial_removal_inventory_keeps_the_attempt_binding_and_detects_later_changes() -> TestResult
    {
        if !in_lock_test_process("attempt_registry::recovery::directories::tests::partial_removal_inventory_keeps_the_attempt_binding_and_detects_later_changes")? {
            return Ok(());
        }
        let (directory, recovery) = fixture()?;
        let root = directory.path().join("attempts").join(key(4)?).join("root");
        // Keep the removed inode pinned so a new root cannot reuse its number.
        let held_root = File::open(&root)?;
        let original = recovery.inventory_unmounted_directories()?;
        fs::remove_dir(&root)?;
        assert!(original.verify_unchanged().is_err());
        drop(original);
        let partial = recovery.inventory_unmounted_directories()?;
        let entry = partial
            .directories()
            .iter()
            .find(|entry| entry.intent().attempt_id() == [4; 16])
            .ok_or("missing surviving attempt")?;
        assert!(entry.identity_was_committed());
        assert_eq!(entry.root_identity(), None);
        partial.verify_unchanged()?;
        private_directory(&root)?;
        assert_ne!(identity(&File::open(&root)?)?, identity(&held_root)?);
        assert!(partial.verify_unchanged().is_err());
        assert!(recovery.inventory_unmounted_directories().is_err());
        assert_eq!(fs::read_dir(directory.path().join("registry"))?.count(), 9);
        Ok(())
    }

    #[test]
    fn temporary_record_cannot_authorize_existing_directory() -> TestResult {
        if !in_lock_test_process("attempt_registry::recovery::directories::tests::temporary_record_cannot_authorize_existing_directory")? {
            return Ok(());
        }
        let (directory, recovery) = fixture()?;
        drop(recovery);
        fs::rename(
            directory.path().join("registry").join(key(2)?),
            directory
                .path()
                .join("registry")
                .join(format!(".planned-{}-123-1", key(2)?)),
        )?;
        let runtime = File::open(directory.path())?;
        let held = super::super::RegistryDirectory::from_runtime_directory(
            &runtime,
            runtime.metadata()?.uid(),
        )?;
        let recovery = SystemdAttemptRecovery::from_directory(held)?;
        assert!(recovery.inventory_unmounted_directories().is_err());
        assert!(directory.path().join("attempts").join(key(2)?).is_dir());
        Ok(())
    }

    #[test]
    fn held_inventory_rejects_parent_and_uncommitted_identity_substitution() -> TestResult {
        if !in_lock_test_process("attempt_registry::recovery::directories::tests::held_inventory_rejects_parent_and_uncommitted_identity_substitution")? {
            return Ok(());
        }
        for fault in 0..4 {
            let (directory, recovery) = fixture()?;
            let inventory = recovery.inventory_unmounted_directories()?;
            let attempts = directory.path().join("attempts");
            let attempt = attempts.join(key(2)?);
            match fault {
                0 => {
                    fs::rename(&attempts, directory.path().join("held"))?;
                    private_directory(&attempts)?;
                }
                1 => {
                    fs::rename(&attempt, directory.path().join("held"))?;
                    private_directory(&attempt)?;
                }
                2 => fs::remove_dir(&attempt)?,
                _ => private_directory(&attempt.join("root"))?,
            }
            assert!(inventory.verify_unchanged().is_err());
        }
        Ok(())
    }

    #[test]
    fn every_inventory_io_boundary_propagates_failure_without_removing_evidence() -> TestResult {
        if !in_lock_test_process("attempt_registry::recovery::directories::tests::every_inventory_io_boundary_propagates_failure_without_removing_evidence")? {
            return Ok(());
        }
        let (directory, recovery) = fixture()?;
        let (result, count) = with_io_fault(None, || recovery.inventory_unmounted_directories());
        drop(result?);
        assert!(count > 0);
        for fail_at in 0..count {
            let (result, observed) =
                with_io_fault(Some(fail_at), || recovery.inventory_unmounted_directories());
            assert!(matches!(result, Err(SystemdAttemptRegistryError::Io(_))));
            assert_eq!(observed, fail_at + 1);
            assert_eq!(fs::read_dir(directory.path().join("registry"))?.count(), 9);
            assert_eq!(fs::read_dir(directory.path().join("attempts"))?.count(), 7);
        }
        Ok(())
    }

    #[test]
    fn recorded_root_entries_hold_only_recorded_attempt_roots() -> TestResult {
        use std::os::fd::AsFd;
        type Change = fn(&std::path::Path, &std::path::Path) -> TestResult;

        if !in_lock_test_process("attempt_registry::recovery::directories::tests::recorded_root_entries_hold_only_recorded_attempt_roots")? {
            return Ok(());
        }
        let attempt = |runtime: &std::path::Path, id| -> TestResult<std::path::PathBuf> {
            Ok(runtime.join("attempts").join(key(id)?))
        };
        // Attempts 4 to 8 recorded both directory identities, 1 to 3 did not.
        // Attempt 4's root is gone, attempt 8's directories are both gone, and
        // an unknown attempt 9 is skipped.
        let (directory, recovery) = fixture()?;
        let runtime = directory.path();
        fs::remove_dir(attempt(runtime, 4)?.join("root"))?;
        fs::remove_dir(attempt(runtime, 8)?.join("root"))?;
        fs::remove_dir(attempt(runtime, 8)?)?;
        private_directory(&attempt(runtime, 9)?)?;
        let entries = recovery.recorded_root_entries()?;
        let ids: Vec<_> = entries
            .iter()
            .map(|entry| entry.intent.planned().attempt_id())
            .collect();
        assert_eq!(ids, (5..=7).map(|id| [id; 16]).collect::<Vec<_>>());
        for (id, entry) in (5..=7).zip(&entries) {
            let path = attempt(runtime, id)?;
            let held = entry.attempt.metadata()?;
            let expected = fs::metadata(&path)?;
            assert_eq!((held.dev(), held.ino()), (expected.dev(), expected.ino()));
            let root = rustix::fs::fstat(entry.root.as_fd())?;
            let expected = fs::metadata(path.join("root"))?;
            assert_eq!((root.st_dev, root.st_ino), (expected.dev(), expected.ino()));
        }
        drop(entries);
        // An unexpected child, a symlinked root, a replaced attempt directory
        // and an unsafe attempt directory each refuse as unsafe; a changed
        // registry requires a new reconciliation.
        let changes: [Change; 5] = [
            |_, attempt| Ok(fs::write(attempt.join("extra"), b"")?),
            |_, attempt| {
                fs::remove_dir(attempt.join("root"))?;
                Ok(symlink("/tmp", attempt.join("root"))?)
            },
            |runtime, attempt| {
                fs::rename(attempt, runtime.join("replaced"))?;
                private_directory(attempt)?;
                private_directory(&attempt.join("root"))
            },
            |_, attempt| {
                Ok(fs::set_permissions(
                    attempt,
                    fs::Permissions::from_mode(0o755),
                )?)
            },
            // Attempt 5's committed intent disappears.
            |runtime, attempt| {
                let key = attempt.file_name().ok_or("no attempt component")?;
                Ok(fs::remove_file(runtime.join("registry").join(key))?)
            },
        ];
        for (index, change) in changes.into_iter().enumerate() {
            let (directory, recovery) = fixture()?;
            change(directory.path(), &attempt(directory.path(), 5)?)?;
            let result = recovery.recorded_root_entries();
            let refused = if index == 4 {
                matches!(
                    result,
                    Err(SystemdAttemptRegistryError::ReconciliationRequired)
                )
            } else {
                matches!(result, Err(SystemdAttemptRegistryError::UnsafeRegistry))
            };
            assert!(refused, "change {index}: {result:?}");
        }
        Ok(())
    }
}
