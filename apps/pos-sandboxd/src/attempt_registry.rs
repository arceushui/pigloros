//! Planned activation ownership, committed before creating attempt resources.
//!
//! The private PAI1 format is exactly a version tag, `AttemptId` and SIM1 digest.
//! The service name and directory component are injectively derived from the
//! `AttemptId`. Unknown versions/stages fail closed. This local record does not
//! replace ADR-069 lifecycle evidence or authorize image activation. The PAI2
//! directory stage adds the held attempt/root device and inode identities.

use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::{Arc, Mutex};

use rustix::fs::{
    flock, openat2, renameat_with, Dir, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags,
};

use crate::TransientServiceUnitName;

mod directory;
mod recovery;
pub use directory::PreparedAttemptDirectory;
pub use recovery::{RecoveredAttemptIntent, RegistryRecoveryEntry, SystemdAttemptRecovery};

const RECORD_SIZE: usize = 52;
const REGISTRY_NAME: &str = "registry";

/// Immutable planned ownership, with no mount or execution authority.
///
/// The provider must supply identities from independently authenticated image
/// admission. Recording these identities does not authenticate them itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedAttemptIntent {
    attempt_id: [u8; 16],
    sim1_digest: [u8; 32],
    unit_name: TransientServiceUnitName,
}

impl PlannedAttemptIntent {
    /// Describe one planned attempt before any directory, mount or unit exists.
    ///
    /// # Errors
    /// Rejects a zero `AttemptId` or zero SIM1 identity.
    pub fn new(
        attempt_id: [u8; 16],
        sim1_digest: [u8; 32],
    ) -> Result<Self, SystemdAttemptRegistryError> {
        if sim1_digest == [0; 32] {
            return Err(SystemdAttemptRegistryError::InvalidIntent);
        }
        TransientServiceUnitName::from_attempt_id(attempt_id)
            .map_err(|_| SystemdAttemptRegistryError::InvalidIntent)
            .map(|unit_name| Self {
                attempt_id,
                sim1_digest,
                unit_name,
            })
    }

    /// The authoritative `AttemptId` supplied by provider admission.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// The selected SIM1 identity recorded for restart reconciliation.
    #[must_use]
    pub const fn sim1_digest(&self) -> [u8; 32] {
        self.sim1_digest
    }

    /// Deterministic unit identity bound by this record's `AttemptId`.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }

    fn encode(&self) -> [u8; RECORD_SIZE] {
        let mut bytes = [0; RECORD_SIZE];
        bytes[..4].copy_from_slice(b"PAI1");
        bytes[4..20].copy_from_slice(&self.attempt_id);
        bytes[20..].copy_from_slice(&self.sim1_digest);
        bytes
    }

    fn decode(bytes: &[u8; RECORD_SIZE]) -> Result<Self, SystemdAttemptRegistryError> {
        if &bytes[..4] != b"PAI1" {
            return Err(SystemdAttemptRegistryError::InvalidIntent);
        }
        let mut attempt = [0; 16];
        let mut image = [0; 32];
        attempt.copy_from_slice(&bytes[4..20]);
        image.copy_from_slice(&bytes[20..]);
        Self::new(attempt, image)
    }
}

/// Closed failures at the durable planned-intent boundary.
#[derive(Debug, thiserror::Error)]
pub enum SystemdAttemptRegistryError {
    /// The fixed directory or retained record is unsafe or has changed identity.
    #[error("unsafe systemd attempt registry")]
    UnsafeRegistry,
    /// An intent has an invalid identity, version, size or binding.
    #[error("invalid planned systemd attempt intent")]
    InvalidIntent,
    /// A previous uncertain write or poisoned lock has closed new commits.
    #[error("systemd attempt registry requires reconciliation")]
    ReconciliationRequired,
    /// An operating-system operation failed; no successful commit is claimed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug)]
struct RegistryDirectory {
    runtime: File,
    file: File,
    owner: u32,
}

impl RegistryDirectory {
    fn open() -> Result<Self, SystemdAttemptRegistryError> {
        let root = registry_io(|| File::open("/"))?;
        validate_directory(&root, 0, false)?;
        let mut parent = open_directory(&root, "run", ResolveFlags::empty())?;
        validate_directory(&parent, 0, false)?;
        for component in ["pigloros", "sandbox"] {
            parent = open_directory(&parent, component, ResolveFlags::NO_XDEV)?;
            validate_directory(&parent, 0, component == "sandbox")?;
        }
        Self::from_runtime_directory(&parent, 0)
    }

    fn from_runtime_directory(
        parent: &File,
        owner: u32,
    ) -> Result<Self, SystemdAttemptRegistryError> {
        validate_directory(parent, owner, true)?;
        let registry = open_directory(parent, REGISTRY_NAME, ResolveFlags::NO_XDEV)?;
        validate_directory(&registry, owner, true)?;
        registry_io(|| {
            flock(&registry, FlockOperation::NonBlockingLockExclusive).map_err(io::Error::from)
        })?;
        Ok(Self {
            runtime: registry_io(|| parent.try_clone())?,
            file: registry,
            owner,
        })
    }
}

/// The fixed root-owned registry at `/run/pigloros/sandbox/registry`.
///
/// Startup provisions the directory with mode 0700. This component records
/// planned and directory ownership only. Restart inventory, reconciliation and
/// subsequent lifecycle extensions must finish before provider admission opens.
#[derive(Debug)]
pub struct SystemdAttemptRegistry {
    directory: Arc<RegistryDirectory>,
    state: Arc<Mutex<RegistryState>>,
}

#[derive(Debug, Default)]
struct RegistryState {
    failed: bool,
    next_sequence: u64,
}

impl SystemdAttemptRegistry {
    /// Open the fixed registry through held, root-owned directory descriptors.
    ///
    /// # Errors
    /// Rejects missing/unsafe directories, symlinks, writable ancestors, a
    /// mount crossing beneath `/run`, permissions other than 0700, another
    /// live owner, or any unreconciled record left by a previous owner.
    pub fn open() -> Result<Self, SystemdAttemptRegistryError> {
        Self::from_directory(RegistryDirectory::open()?)
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn from_runtime_directory(
        parent: &File,
        owner: u32,
    ) -> Result<Self, SystemdAttemptRegistryError> {
        Self::from_directory(RegistryDirectory::from_runtime_directory(parent, owner)?)
    }

    fn from_directory(directory: RegistryDirectory) -> Result<Self, SystemdAttemptRegistryError> {
        require_empty(&directory.file)?;
        Ok(Self {
            directory: Arc::new(directory),
            state: Arc::new(Mutex::new(RegistryState::default())),
        })
    }

    /// Commit planned ownership without replacing an existing `AttemptId` key.
    ///
    /// The file is written and fsynced before `RENAME_NOREPLACE`; the registry
    /// parent is fsynced before a committed value is returned. No attempt
    /// directory, mount or unit is created. Any failed commit closes this owner
    /// to further commits; recognizable temporary records remain for recovery.
    ///
    /// # Errors
    /// Rejects duplicates, unsafe state, and write/rename/fsync failures. A
    /// failure after rename may have published the record; recovery must inspect
    /// it instead of treating an error as proof that no record exists.
    pub fn commit_planned(
        &self,
        intent: &PlannedAttemptIntent,
    ) -> Result<CommittedPlannedAttempt, SystemdAttemptRegistryError> {
        let mut state = self
            .state
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
                self.write_planned(intent, sequence)
            });
        state.failed = result.is_err();
        drop(state);
        result.map(|()| CommittedPlannedAttempt {
            directory: Arc::clone(&self.directory),
            state: Arc::clone(&self.state),
            intent: intent.clone(),
        })
    }

    fn write_planned(
        &self,
        intent: &PlannedAttemptIntent,
        sequence: u64,
    ) -> Result<(), SystemdAttemptRegistryError> {
        publish_record(
            &self.directory,
            intent,
            sequence,
            &intent.encode(),
            RenameFlags::NOREPLACE,
        )?;
        verify_intent(&self.directory, intent)
    }
}

/// Evidence that one planned record was published and both fsyncs succeeded.
///
/// It retains the registry descriptor for readback. It grants no authority to
/// mount, execute, remove resources, or skip provider current-generation checks.
#[derive(Debug)]
pub struct CommittedPlannedAttempt {
    directory: Arc<RegistryDirectory>,
    state: Arc<Mutex<RegistryState>>,
    intent: PlannedAttemptIntent,
}

impl CommittedPlannedAttempt {
    /// The exact planned ownership record committed by this operation.
    #[must_use]
    pub const fn intent(&self) -> &PlannedAttemptIntent {
        &self.intent
    }

    /// Reopen only this key beneath the retained registry and verify its record.
    ///
    /// # Errors
    /// Rejects removal, substitution, unsafe metadata and altered record bytes.
    /// Any detected contradiction closes the registry owner to further commits.
    pub fn verify_record(&self) -> Result<(), SystemdAttemptRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SystemdAttemptRegistryError::ReconciliationRequired)?;
        let result = verify_intent(&self.directory, &self.intent);
        state.failed |= result.is_err();
        result
    }
}

fn publish_record(
    directory: &RegistryDirectory,
    intent: &PlannedAttemptIntent,
    sequence: u64,
    bytes: &[u8],
    rename: RenameFlags,
) -> Result<(), SystemdAttemptRegistryError> {
    validate_directory(&directory.file, directory.owner, true)?;
    let temporary = format!(
        ".planned-{}-{}-{sequence}",
        intent.unit_name.attempt_component(),
        std::process::id()
    );
    let mut file = File::from(registry_io(|| {
        openat2(
            &directory.file,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(io::Error::from)
    })?);
    registry_io(|| file.write_all(bytes))?;
    registry_io(|| file.sync_all())?;
    registry_io(|| {
        renameat_with(
            &directory.file,
            temporary.as_str(),
            &directory.file,
            intent.unit_name.attempt_component(),
            rename,
        )
        .map_err(io::Error::from)
    })?;
    registry_io(|| directory.file.sync_all())?;
    Ok(())
}

fn verify_intent(
    directory: &RegistryDirectory,
    intent: &PlannedAttemptIntent,
) -> Result<(), SystemdAttemptRegistryError> {
    read_record(directory, intent).and_then(|observed| {
        if observed == *intent {
            Ok(())
        } else {
            Err(SystemdAttemptRegistryError::InvalidIntent)
        }
    })
}

// Keep filesystem failure injection at the I/O boundary. Production always
// performs the supplied operation; only tests can fail an operation before it
// starts, including fsync/readback failures after a record was published.
fn registry_io<T>(operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    #[cfg(test)]
    tests::before_io()?;
    operation()
}

fn open_directory(
    parent: &File,
    component: &str,
    mount_rule: ResolveFlags,
) -> Result<File, SystemdAttemptRegistryError> {
    registry_io(|| {
        openat2(
            parent,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | mount_rule,
        )
        .map(File::from)
        .map_err(io::Error::from)
    })
    .map_err(Into::into)
}

fn require_empty(directory: &File) -> Result<(), SystemdAttemptRegistryError> {
    let entries = registry_io(|| Dir::read_from(directory).map_err(io::Error::from))?;
    for entry in entries {
        let entry = registry_io(|| entry.map_err(io::Error::from))?;
        if entry.file_name().to_bytes() != b"." && entry.file_name().to_bytes() != b".." {
            return Err(SystemdAttemptRegistryError::ReconciliationRequired);
        }
    }
    Ok(())
}

fn validate_directory(
    file: &File,
    owner: u32,
    private: bool,
) -> Result<(), SystemdAttemptRegistryError> {
    let metadata = registry_io(|| file.metadata())?;
    if !metadata.is_dir()
        || metadata.uid() != owner
        || metadata.mode() & 0o022 != 0
        || private && metadata.mode() & 0o7777 != 0o700
    {
        return Err(SystemdAttemptRegistryError::UnsafeRegistry);
    }
    Ok(())
}

fn read_record(
    directory: &RegistryDirectory,
    expected: &PlannedAttemptIntent,
) -> Result<PlannedAttemptIntent, SystemdAttemptRegistryError> {
    let bytes = read_record_bytes::<RECORD_SIZE>(directory, &expected.unit_name)?;
    PlannedAttemptIntent::decode(&bytes).and_then(|intent| {
        if intent.attempt_id == expected.attempt_id {
            Ok(intent)
        } else {
            Err(SystemdAttemptRegistryError::InvalidIntent)
        }
    })
}

fn read_record_bytes<const N: usize>(
    directory: &RegistryDirectory,
    unit: &TransientServiceUnitName,
) -> Result<[u8; N], SystemdAttemptRegistryError> {
    validate_directory(&directory.file, directory.owner, true)?;
    let file = File::from(registry_io(|| {
        openat2(
            &directory.file,
            unit.attempt_component(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(io::Error::from)
    })?);
    let metadata = registry_io(|| file.metadata())?;
    if !metadata.is_file()
        || metadata.uid() != directory.owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != N as u64
    {
        return Err(SystemdAttemptRegistryError::UnsafeRegistry);
    }
    let mut bytes = [0; N];
    registry_io(|| file.read_exact_at(&mut bytes, 0))?;
    Ok(bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    std::thread_local! {
        static IO_FAULT: Cell<(usize, Option<usize>)> = const { Cell::new((0, None)) };
    }

    pub(super) fn before_io() -> io::Result<()> {
        IO_FAULT.with(|state| {
            let (count, fail_at) = state.get();
            state.set((count + 1, fail_at));
            if fail_at == Some(count) {
                Err(io::Error::other("injected registry I/O failure"))
            } else {
                Ok(())
            }
        })
    }

    struct RestoreIoFault((usize, Option<usize>));

    impl Drop for RestoreIoFault {
        fn drop(&mut self) {
            IO_FAULT.with(|state| state.set(self.0));
        }
    }

    pub(super) fn with_io_fault<T>(
        fail_at: Option<usize>,
        operation: impl FnOnce() -> T,
    ) -> (T, usize) {
        let _restore = RestoreIoFault(IO_FAULT.with(|state| state.replace((0, fail_at))));
        let result = operation();
        (result, IO_FAULT.with(|state| state.get().0))
    }

    // A concurrent test's fork can retain an O_CLOEXEC flock descriptor until
    // exec. Run lock-release assertions alone in a fresh process, opening their
    // fixtures only after exec; do not accept lock contention as reconciliation.
    pub(super) fn in_lock_test_process(name: &str) -> TestResult<bool> {
        const CHILD: &str = "PIGLOROS_REGISTRY_LOCK_TEST";
        if std::env::var(CHILD).as_deref() == Ok(name) {
            return Ok(true);
        }
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", name, "--test-threads=1"])
            .env(CHILD, name)
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.lines().any(|line| {
                    line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")
                }),
            "isolated lock test {name} did not pass exactly once: {:?}\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(false)
    }

    #[test]
    fn isolated_lock_test_rejects_an_unmatched_filter() {
        let result = std::panic::catch_unwind(|| {
            in_lock_test_process("attempt_registry::tests::no_such_lock_test")
        });
        assert!(result.is_err());
    }

    pub(super) fn fixture() -> TestResult<(tempfile::TempDir, File, u32)> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        fs::create_dir(directory.path().join(REGISTRY_NAME))?;
        fs::set_permissions(
            directory.path().join(REGISTRY_NAME),
            fs::Permissions::from_mode(0o700),
        )?;
        let parent = File::open(directory.path())?;
        let owner = parent.metadata()?.uid();
        Ok((directory, parent, owner))
    }

    #[test]
    fn fixed_public_registry_opens_only_valid_runtime_tree() -> TestResult {
        if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_none() {
            let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/run-isolated-test.sh");
            let output = std::process::Command::new(runner)
                .arg(std::env::current_exe()?)
                .arg("attempt_registry::tests::fixed_public_registry_opens_only_valid_runtime_tree")
                .output()?;
            assert!(
                output.status.success(),
                "isolated registry test failed: {:?}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }
        assert_eq!(fs::metadata("/run")?.uid(), 0);
        assert!(!std::path::Path::new("/run/pigloros").exists());
        assert!(SystemdAttemptRegistry::open().is_err());
        for component in [
            "/run/pigloros",
            "/run/pigloros/sandbox",
            "/run/pigloros/sandbox/registry",
        ] {
            fs::create_dir(component)?;
            fs::set_permissions(component, fs::Permissions::from_mode(0o700))?;
        }
        // The isolated runner mounts /run separately. Exercise the very same
        // kernel traversal rule used below the public factory's held /run FD.
        let root = File::open("/")?;
        assert_ne!(root.metadata()?.dev(), fs::metadata("/run")?.dev());
        assert!(open_directory(&root, "run", ResolveFlags::NO_XDEV).is_err());
        for component in [
            "/run",
            "/run/pigloros",
            "/run/pigloros/sandbox",
            "/run/pigloros/sandbox/registry",
        ] {
            let original = fs::metadata(component)?.permissions();
            fs::set_permissions(component, fs::Permissions::from_mode(0o777))?;
            assert!(SystemdAttemptRegistry::open().is_err());
            fs::set_permissions(component, original)?;
        }
        fs::rename(
            "/run/pigloros/sandbox/registry",
            "/run/pigloros/sandbox/held",
        )?;
        symlink("held", "/run/pigloros/sandbox/registry")?;
        assert!(SystemdAttemptRegistry::open().is_err());
        fs::remove_file("/run/pigloros/sandbox/registry")?;
        fs::rename(
            "/run/pigloros/sandbox/held",
            "/run/pigloros/sandbox/registry",
        )?;
        let (opened, operation_count) = with_io_fault(None, SystemdAttemptRegistry::open);
        drop(opened?);
        for fail_at in 0..operation_count {
            let (result, observed) = with_io_fault(Some(fail_at), SystemdAttemptRegistry::open);
            assert!(matches!(result, Err(SystemdAttemptRegistryError::Io(_))));
            assert_eq!(observed, fail_at + 1);
            assert_eq!(fs::read_dir("/run/pigloros/sandbox/registry")?.count(), 0);
        }
        let registry = SystemdAttemptRegistry::open()?;
        let intent = PlannedAttemptIntent::new([1; 16], [2; 32])?;
        let committed = registry.commit_planned(&intent)?;
        committed.verify_record()?;
        assert!(SystemdAttemptRegistry::open().is_err());
        drop(registry);
        committed.verify_record()?;
        drop(committed);
        assert!(matches!(
            SystemdAttemptRegistry::open(),
            Err(SystemdAttemptRegistryError::ReconciliationRequired)
        ));
        Ok(())
    }

    #[test]
    fn planned_identity_has_one_exact_closed_encoding() -> TestResult {
        assert!(PlannedAttemptIntent::new([0; 16], [2; 32]).is_err());
        assert!(PlannedAttemptIntent::new([1; 16], [0; 32]).is_err());
        let intent = PlannedAttemptIntent::new([0xab; 16], [2; 32])?;
        assert_eq!(intent.attempt_id(), [0xab; 16]);
        assert_eq!(intent.sim1_digest(), [2; 32]);
        assert_eq!(
            intent.unit_name().as_str(),
            "pigloros-attempt-abababababababababababababababab.service"
        );
        assert_eq!(
            intent.unit_name().attempt_component(),
            "abababababababababababababababab"
        );
        let expected = [
            0x50, 0x41, 0x49, 0x31, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        ];
        assert_eq!(intent.encode(), expected);
        assert_eq!(PlannedAttemptIntent::decode(&expected)?, intent);
        for index in [0, 3] {
            let mut bytes = intent.encode();
            bytes[index] ^= 1;
            assert!(PlannedAttemptIntent::decode(&bytes).is_err());
        }
        assert!(PlannedAttemptIntent::decode(&[0; RECORD_SIZE]).is_err());
        Ok(())
    }

    #[test]
    fn eight_plans_commit_exact_records_without_creating_attempt_resources() -> TestResult {
        let (directory, parent, owner) = fixture()?;
        let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
        for id in 1..=8 {
            let intent = PlannedAttemptIntent::new([id; 16], [id; 32])?;
            let committed = registry.commit_planned(&intent)?;
            assert_eq!(committed.intent(), &intent);
            committed.verify_record()?;
            let path = directory
                .path()
                .join(REGISTRY_NAME)
                .join(intent.unit_name().attempt_component());
            assert_eq!(fs::read(path)?, intent.encode());
        }
        assert_eq!(
            fs::read_dir(directory.path().join(REGISTRY_NAME))?.count(),
            8
        );
        assert_eq!(fs::read_dir(directory.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn duplicate_key_never_replaces_record_and_closes_further_commits() -> TestResult {
        let (directory, parent, owner) = fixture()?;
        let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
        let intent = PlannedAttemptIntent::new([1; 16], [2; 32])?;
        let committed = registry.commit_planned(&intent)?;
        let conflicting = PlannedAttemptIntent::new([1; 16], [3; 32])?;
        assert!(registry.commit_planned(&conflicting).is_err());
        committed.verify_record()?;
        assert!(registry
            .commit_planned(&PlannedAttemptIntent::new([4; 16], [5; 32])?)
            .is_err());
        let names = fs::read_dir(directory.path().join(REGISTRY_NAME))?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(names.len(), 2);
        assert!(names
            .iter()
            .any(|name| name.to_string_lossy().starts_with(".planned-")));
        Ok(())
    }

    #[test]
    fn every_commit_io_failure_closes_owner_and_retains_recovery_records() -> TestResult {
        if !in_lock_test_process("attempt_registry::tests::every_commit_io_failure_closes_owner_and_retains_recovery_records")? {
            return Ok(());
        }
        let intent = PlannedAttemptIntent::new([1; 16], [2; 32])?;
        let operation_count = {
            let (_directory, parent, owner) = fixture()?;
            let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
            let (result, count) = with_io_fault(None, || registry.commit_planned(&intent));
            result?;
            count
        };
        let mut observed_temporary = false;
        let mut observed_published = false;
        for fail_at in 0..operation_count {
            let (directory, parent, owner) = fixture()?;
            let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
            let (result, observed) =
                with_io_fault(Some(fail_at), || registry.commit_planned(&intent));
            assert!(matches!(result, Err(SystemdAttemptRegistryError::Io(_))));
            assert_eq!(observed, fail_at + 1);
            assert!(matches!(
                registry.commit_planned(&intent),
                Err(SystemdAttemptRegistryError::ReconciliationRequired)
            ));
            let entries = fs::read_dir(directory.path().join(REGISTRY_NAME))?
                .collect::<Result<Vec<_>, _>>()?;
            assert!(entries.len() <= 1);
            for entry in &entries {
                let name = entry.file_name();
                let bytes = fs::read(entry.path())?;
                if name == intent.unit_name.attempt_component() {
                    observed_published = true;
                    assert_eq!(bytes, intent.encode());
                } else {
                    observed_temporary = true;
                    assert_eq!(
                        name,
                        format!(
                            ".planned-{}-{}-1",
                            intent.unit_name.attempt_component(),
                            std::process::id()
                        )
                        .as_str()
                    );
                    assert!(bytes.is_empty() || bytes == intent.encode());
                }
            }
            // No attempt directory was created; dropping the failed owner
            // must neither remove evidence nor make a nonempty registry live.
            assert_eq!(fs::read_dir(directory.path())?.count(), 1);
            drop(registry);
            assert_eq!(
                fs::read_dir(directory.path().join(REGISTRY_NAME))?.count(),
                entries.len()
            );
            if !entries.is_empty() {
                let reopened = SystemdAttemptRegistry::from_runtime_directory(&parent, owner);
                assert!(
                    matches!(
                        reopened,
                        Err(SystemdAttemptRegistryError::ReconciliationRequired)
                    ),
                    "reopen after injected I/O failure {fail_at}: {reopened:?}"
                );
            }
        }
        assert!(observed_temporary);
        assert!(observed_published);
        Ok(())
    }

    #[test]
    fn every_readback_io_failure_closes_owner_without_removing_record() -> TestResult {
        let intent = PlannedAttemptIntent::new([1; 16], [2; 32])?;
        let operation_count = {
            let (_directory, parent, owner) = fixture()?;
            let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
            let committed = registry.commit_planned(&intent)?;
            let (result, count) = with_io_fault(None, || committed.verify_record());
            result?;
            count
        };
        for fail_at in 0..operation_count {
            let (directory, parent, owner) = fixture()?;
            let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
            let committed = registry.commit_planned(&intent)?;
            let (result, observed) = with_io_fault(Some(fail_at), || committed.verify_record());
            assert!(matches!(result, Err(SystemdAttemptRegistryError::Io(_))));
            assert_eq!(observed, fail_at + 1);
            assert!(matches!(
                registry.commit_planned(&intent),
                Err(SystemdAttemptRegistryError::ReconciliationRequired)
            ));
            assert_eq!(
                fs::read(
                    directory
                        .path()
                        .join(REGISTRY_NAME)
                        .join(intent.unit_name.attempt_component())
                )?,
                intent.encode()
            );
        }
        Ok(())
    }

    #[test]
    fn owner_lock_survives_until_all_committed_handles_drop() -> TestResult {
        if !in_lock_test_process(
            "attempt_registry::tests::owner_lock_survives_until_all_committed_handles_drop",
        )? {
            return Ok(());
        }
        let (_directory, parent, owner) = fixture()?;
        let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
        assert!(SystemdAttemptRegistry::from_runtime_directory(&parent, owner).is_err());
        let committed = registry.commit_planned(&PlannedAttemptIntent::new([1; 16], [2; 32])?)?;
        drop(registry);
        assert!(SystemdAttemptRegistry::from_runtime_directory(&parent, owner).is_err());
        committed.verify_record()?;
        drop(committed);
        assert!(matches!(
            SystemdAttemptRegistry::from_runtime_directory(&parent, owner),
            Err(SystemdAttemptRegistryError::ReconciliationRequired)
        ));
        Ok(())
    }

    #[test]
    fn temporary_or_unknown_restart_state_requires_reconciliation() -> TestResult {
        for name in [".planned-interrupted", "unrecognized"] {
            let (directory, parent, owner) = fixture()?;
            fs::write(directory.path().join(REGISTRY_NAME).join(name), b"partial")?;
            assert!(matches!(
                SystemdAttemptRegistry::from_runtime_directory(&parent, owner),
                Err(SystemdAttemptRegistryError::ReconciliationRequired)
            ));
        }
        Ok(())
    }

    #[test]
    fn unsafe_registry_and_parent_are_rejected() -> TestResult {
        let (directory, parent, owner) = fixture()?;
        assert!(SystemdAttemptRegistry::from_runtime_directory(&parent, owner ^ 1).is_err());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))?;
        assert!(SystemdAttemptRegistry::from_runtime_directory(&parent, owner).is_err());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(
            directory.path().join(REGISTRY_NAME),
            fs::Permissions::from_mode(0o750),
        )?;
        assert!(SystemdAttemptRegistry::from_runtime_directory(&parent, owner).is_err());
        fs::remove_dir(directory.path().join(REGISTRY_NAME))?;
        symlink(directory.path(), directory.path().join(REGISTRY_NAME))?;
        assert!(SystemdAttemptRegistry::from_runtime_directory(&parent, owner).is_err());
        fs::remove_file(directory.path().join(REGISTRY_NAME))?;
        fs::write(directory.path().join(REGISTRY_NAME), b"not a directory")?;
        let regular = File::open(directory.path().join(REGISTRY_NAME))?;
        assert!(SystemdAttemptRegistry::from_runtime_directory(&regular, owner).is_err());
        Ok(())
    }

    #[test]
    fn readback_rejects_changed_record_identity_and_metadata() -> TestResult {
        for corruption in 0..6 {
            let (directory, parent, owner) = fixture()?;
            let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
            let intent = PlannedAttemptIntent::new([1; 16], [2; 32])?;
            let committed = registry.commit_planned(&intent)?;
            let path = directory
                .path()
                .join(REGISTRY_NAME)
                .join(intent.unit_name().attempt_component());
            match corruption {
                0 => fs::write(&path, PlannedAttemptIntent::new([1; 16], [3; 32])?.encode())?,
                1 => fs::write(&path, PlannedAttemptIntent::new([3; 16], [2; 32])?.encode())?,
                2 => fs::write(&path, b"short")?,
                3 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?,
                4 => fs::hard_link(&path, directory.path().join("alias"))?,
                _ => fs::remove_file(&path)?,
            }
            assert!(committed.verify_record().is_err());
            assert!(registry
                .commit_planned(&PlannedAttemptIntent::new([4; 16], [5; 32])?)
                .is_err());
        }
        Ok(())
    }

    #[test]
    fn exhausted_or_poisoned_owner_cannot_publish_more_records() -> TestResult {
        let (_directory, parent, owner) = fixture()?;
        let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
        let intent = PlannedAttemptIntent::new([1; 16], [2; 32])?;
        let committed = registry.commit_planned(&intent)?;
        registry
            .state
            .lock()
            .map_err(|_| "unexpected poisoned fixture")?
            .next_sequence = u64::MAX;
        assert!(registry.commit_planned(&intent).is_err());
        assert!(std::panic::catch_unwind(|| {
            let _guard = registry.state.lock();
            std::panic::resume_unwind(Box::new(()));
        })
        .is_err());
        assert!(registry.commit_planned(&intent).is_err());
        assert!(committed.verify_record().is_err());
        Ok(())
    }
}
