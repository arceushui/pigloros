//! Private files for the provider-owned, source-authenticated staging context.

use super::super::HeldImageAdmission;
use super::{
    AdmittedProviderExecution, PreparedProviderExecution, ProviderExecutionPolicy, StagingCharge,
    StagingError,
};
#[cfg(test)]
use super::{StagingLedger, StagingLimits, StagingUsage};
use rustix::fs::{openat2, unlinkat, AtFlags, Mode, OFlags, ResolveFlags};
use std::{
    fs::File,
    io,
    os::unix::{fs::MetadataExt as _, net::UnixStream},
    sync::Arc,
};

/// A borrowed entry keeps the complete verified input and its reservation alive.
#[derive(Debug)]
pub struct AdmittedEntry<'a> {
    execution: &'a Arc<AdmittedProviderExecution>,
}

impl AdmittedEntry<'_> {
    /// Descriptor-bearing image evidence from the same verified exchange.
    #[must_use]
    pub fn admission(&self) -> HeldImageAdmission<'_> {
        self.execution.image_admission()
    }

    /// Independently authenticated execution limits and readback commitment.
    #[must_use]
    pub fn policy(&self) -> &ProviderExecutionPolicy {
        self.execution.policy()
    }

    /// Retain the exact admitted context through execution and release.
    #[must_use]
    pub fn retain(&self) -> Arc<AdmittedProviderExecution> {
        Arc::clone(self.execution)
    }

    /// Recheck fixed installation and the live control floor before launch.
    ///
    /// # Errors
    /// Refuses changed authority or raised control floors.
    pub fn recheck(&self) -> Result<(), StagingError> {
        self.execution.recheck().map(|_| ())
    }
}

// Exclusive creation of a private, close-on-exec file. `RESOLVE_NO_SYMLINKS`
// also rejects a symlink in the final component, so `O_NOFOLLOW` adds nothing.
const INPUT_OPEN_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::CLOEXEC);
const INPUT_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const INPUT_RESOLVE: ResolveFlags = ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS);

/// A held, private directory that backs staged input files.
#[derive(Debug)]
pub struct StagingDirectory {
    directory: File,
}

impl StagingDirectory {
    /// Adopt a held directory descriptor.
    ///
    /// The caller opens the provider's fixed path through held, symlink-free
    /// descriptors. This verifies the directory is owned by `owner` and has
    /// mode 0700, so no other principal can create, replace or read entries.
    ///
    /// # Errors
    /// `UnsafeDirectory` for a non-directory, another owner or any group/other
    /// permission; `Io` if it cannot be inspected.
    pub fn from_held_directory(directory: File, owner: u32) -> Result<Self, StagingError> {
        directory
            .metadata()
            .map_err(StagingError::from)
            .and_then(|metadata| {
                if !metadata.is_dir()
                    || metadata.uid() != owner
                    || metadata.mode() & 0o7777 != 0o700
                {
                    Err(StagingError::UnsafeDirectory)
                } else {
                    Ok(Self { directory })
                }
            })
    }

    /// Create the exclusive, non-executable file that stages one input.
    ///
    /// The name is the lowercase hexadecimal of `name`, a provider-issued
    /// identity, so it cannot traverse. An existing entry of any kind,
    /// including a symlink, is never adopted.
    ///
    /// # Errors
    /// `Io` when the entry exists or cannot be created.
    pub fn create_input(
        &self,
        name: [u8; 16],
        prepared: PreparedProviderExecution,
    ) -> Result<StagedInput, StagingError> {
        self.create_file(name, prepared.staging_charge())
            .map(|staged| StagedInput { staged, prepared })
    }

    fn create_file(
        &self,
        name: [u8; 16],
        reservation: StagingCharge,
    ) -> Result<StagedFile, StagingError> {
        reservation.recheck()?;
        let name = hex_name(name);
        self.directory
            .try_clone()
            .map_err(StagingError::from)
            .and_then(|directory| {
                openat2(
                    &self.directory,
                    &name,
                    INPUT_OPEN_FLAGS,
                    INPUT_MODE,
                    INPUT_RESOLVE,
                )
                .map_err(|errno| StagingError::Io(io::Error::from(errno)))
                .map(|file| StagedFile {
                    file: File::from(file),
                    directory,
                    name,
                    reservation,
                })
            })
    }
}

fn hex_name(identity: [u8; 16]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    identity
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(DIGITS[usize::from(nibble)]))
        .collect()
}

#[derive(Debug)]
struct StagedFile {
    file: File,
    directory: File,
    name: String,
    reservation: StagingCharge,
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if unlinkat(&self.directory, &self.name, AtFlags::empty()).is_err() {
            self.reservation.record_leak();
        }
    }
}

/// A private input awaiting the complete, grant-bound SBC1 stream.
#[derive(Debug)]
pub struct StagedInput {
    staged: StagedFile,
    prepared: PreparedProviderExecution,
}

impl StagedInput {
    /// Verify descriptor, framing and every selected case field before admission.
    ///
    /// # Errors
    /// Refuses incomplete, foreign, expired or substituted input and authority.
    pub fn receive(self, stream: &mut UnixStream) -> Result<VerifiedStagedInput, StagingError> {
        let Self { staged, prepared } = self;
        let execution = prepared.receive_input(stream, &staged.file)?;
        Ok(VerifiedStagedInput {
            _staged: staged,
            execution: Arc::new(execution),
        })
    }
}

/// Complete input and policy, retaining its private file until unlink.
#[derive(Debug)]
pub struct VerifiedStagedInput {
    _staged: StagedFile,
    execution: Arc<AdmittedProviderExecution>,
}

impl VerifiedStagedInput {
    /// Borrow the only production entry constructor's admitted context.
    #[must_use]
    pub const fn entry(&self) -> AdmittedEntry<'_> {
        AdmittedEntry {
            execution: &self.execution,
        }
    }

    /// The verified complete input length.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.execution.policy().input_descriptor().byte_length
    }

    /// Whether the verified input is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read only the descriptor checked by complete EAI1 verification.
    ///
    /// # Errors
    /// Returns descriptor I/O errors, including reads beyond its complete input.
    pub fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()> {
        self.execution.read_exact_at(buffer, offset)
    }

    /// Reserve this attempt's bounded output, retaining its attempt slot.
    ///
    /// # Errors
    /// Refuses duplicate output, ID-8 excess or aggregate overflow.
    pub fn reserve_output(&self, bytes: u64) -> Result<StagingCharge, StagingError> {
        self.execution.reserve_output(bytes)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    const LIMITS: StagingLimits = StagingLimits {
        aggregate_bytes: 100,
    };

    fn directory() -> Result<(tempfile::TempDir, StagingDirectory), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let held = File::open(temporary.path())?;
        let owner = held.metadata()?.uid();
        Ok((
            temporary,
            StagingDirectory::from_held_directory(held, owner)?,
        ))
    }

    #[test]
    fn creation_never_adopts_an_existing_entry_or_follows_a_symlink() -> TestResult {
        let (temporary, staging) = directory()?;
        let ledger = StagingLedger::new(LIMITS);
        let outside = tempfile::tempdir()?;
        let target = outside.path().join("victim");
        symlink(&target, temporary.path().join("01".repeat(16)))?;
        let result = staging.create_file([1; 16], ledger.reserve_storage(1)?);
        assert!(matches!(result, Err(StagingError::Io(_))));
        assert!(!target.exists());
        fs::write(temporary.path().join("02".repeat(16)), b"x")?;
        assert!(staging
            .create_file([2; 16], ledger.reserve_storage(1)?)
            .is_err());
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn a_file_removed_underneath_is_counted_as_leaked() -> TestResult {
        let (temporary, staging) = directory()?;
        let ledger = StagingLedger::new(LIMITS);
        let input = staging.create_file([3; 16], ledger.reserve_storage(1)?)?;

        fs::remove_file(temporary.path().join("03".repeat(16)))?;
        drop(input);
        assert_eq!(ledger.usage().leaked_files, 1);
        assert!(matches!(
            ledger.reserve_storage(0),
            Err(StagingError::CleanupFailed)
        ));
        Ok(())
    }

    #[test]
    fn residual_file_after_failed_unlink_closes_storage_and_already_prepared_creation() -> TestResult
    {
        use std::os::unix::fs::FileExt as _;

        let (temporary, staging) = directory()?;
        let ledger = StagingLedger::new(LIMITS);
        let input = staging.create_file([4; 16], ledger.reserve_storage(8)?)?;
        input.file.write_all_at(b"residual", 0)?;
        let held = ledger.reserve_storage(1)?;
        let leaf = temporary.path().join("04".repeat(16));
        let residual = temporary.path().join("residual");
        fs::rename(&leaf, &residual)?;
        fs::create_dir(&leaf)?; // unlinkat without REMOVEDIR must fail, even as root.
        drop(input);
        assert_eq!(fs::read(&residual)?, b"residual");
        assert_eq!(ledger.usage().leaked_files, 1);
        assert!(matches!(
            ledger.reserve_storage(0),
            Err(StagingError::CleanupFailed)
        ));
        assert!(matches!(
            staging.create_file([5; 16], held),
            Err(StagingError::CleanupFailed)
        ));
        assert!(!temporary.path().join("05".repeat(16)).exists());
        assert_eq!(ledger.usage().reserved_bytes, 0);
        Ok(())
    }

    #[test]
    fn directory_must_be_private_owned_and_a_directory() -> TestResult {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))?;
        let held = File::open(temporary.path())?;
        let owner = held.metadata()?.uid();
        assert!(matches!(
            StagingDirectory::from_held_directory(held.try_clone()?, owner),
            Err(StagingError::UnsafeDirectory)
        ));
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        assert!(matches!(
            StagingDirectory::from_held_directory(held, owner + 1),
            Err(StagingError::UnsafeDirectory)
        ));
        let file = temporary.path().join("file");
        fs::write(&file, b"")?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o700))?;
        assert!(matches!(
            StagingDirectory::from_held_directory(File::open(&file)?, owner),
            Err(StagingError::UnsafeDirectory)
        ));
        Ok(())
    }
}
