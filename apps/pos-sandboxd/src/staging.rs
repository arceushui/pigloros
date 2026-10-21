//! Provider-owned aggregate payload staging (ADR-069 section 4, #441).
//!
//! [`StagingLedger`] is the atomic accounting state machine: a queued-transfer
//! slot (`QueuedRequests`), an attempt slot (`ConcurrentAttempts`, for output
//! transfers and unreconciled terminal output) and a checked aggregate byte
//! cap. Every reservation is an RAII value, so every EOF, timeout,
//! cancellation, validation failure and successful reconcile releases it by
//! dropping it. [`StagingDirectory`] holds the root-private files that back
//! the bytes: they are created exclusively beneath a held directory descriptor,
//! never follow a symlink, are not executable, and are handed out only as a
//! [`VerifiedStagedInput`] after the declared length arrived in full.
//!
//! The limits are supplied by the composition root from authenticated ELM1
//! and provider configuration. This module never defaults or guesses one.

use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustix::fs::{openat2, unlinkat, AtFlags, Mode, OFlags, ResolveFlags};

/// The exact limits one ledger enforces. Zero is a literal zero-capacity ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagingLimits {
    /// Checked aggregate provider staging hard cap in bytes.
    pub aggregate_bytes: u64,
    /// ELM1 limit 14: incomplete input transfers.
    pub queued_requests: u64,
    /// ELM1 limit 13: output transfers and unreconciled terminal output.
    pub concurrent_attempts: u64,
}

/// A consistent snapshot of the ledger counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StagingUsage {
    /// Bytes reserved against the aggregate cap.
    pub reserved_bytes: u64,
    /// Incomplete input transfers holding a queued slot.
    pub queued_inputs: u64,
    /// Output transfers and retained terminal outputs holding an attempt slot.
    pub attempts: u64,
    /// Staged files that could not be unlinked when their owner was dropped.
    pub leaked_files: u64,
}

/// Closed staging failures.
#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    /// `QueuedRequests` incomplete input transfers already exist.
    #[error("staging queue is full")]
    QueueFull,
    /// `ConcurrentAttempts` output reservations already exist.
    #[error("staging attempt slots are exhausted")]
    AttemptsExhausted,
    /// The declared length does not fit the aggregate staging cap.
    #[error("staging aggregate cap would be exceeded")]
    AggregateExceeded,
    /// The directory is not a private directory owned by the provider.
    #[error("staging directory is unsafe")]
    UnsafeDirectory,
    /// More bytes than the reservation declared were offered.
    #[error("staged input exceeds its reservation")]
    ExceedsReservation,
    /// The transfer ended before the declared length arrived.
    #[error("staged input is incomplete")]
    Incomplete,
    /// An operating-system operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug)]
struct Shared {
    limits: StagingLimits,
    usage: Mutex<StagingUsage>,
}

impl Shared {
    fn usage(&self) -> MutexGuard<'_, StagingUsage> {
        // The counters are plain integers updated in one step, so a poisoned
        // lock cannot expose a torn value.
        self.usage.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The atomic staging accounting state machine.
#[derive(Clone, Debug)]
pub struct StagingLedger {
    shared: Arc<Shared>,
}

impl StagingLedger {
    /// Create a ledger enforcing exactly `limits`.
    #[must_use]
    pub fn new(limits: StagingLimits) -> Self {
        Self {
            shared: Arc::new(Shared {
                limits,
                usage: Mutex::new(StagingUsage::default()),
            }),
        }
    }

    /// Current counters.
    #[must_use]
    pub fn usage(&self) -> StagingUsage {
        *self.shared.usage()
    }

    /// Reserve a queued-transfer slot and `bytes` of aggregate staging.
    ///
    /// Both are taken under one lock; a failure takes neither.
    ///
    /// # Errors
    /// `QueueFull` at `QueuedRequests` incomplete inputs, `AggregateExceeded`
    /// when the checked sum would pass the cap.
    pub fn reserve_input(&self, bytes: u64) -> Result<StagingReservation, StagingError> {
        let mut usage = self.shared.usage();
        if usage.queued_inputs >= self.shared.limits.queued_requests {
            return Err(StagingError::QueueFull);
        }
        usage.reserved_bytes = self.checked_total(&usage, bytes)?;
        usage.queued_inputs += 1;
        drop(usage);
        Ok(self.reservation(bytes, true, false))
    }

    /// Reserve an attempt slot and `bytes` of aggregate staging for output.
    ///
    /// # Errors
    /// `AttemptsExhausted` at `ConcurrentAttempts`, `AggregateExceeded` when
    /// the checked sum would pass the cap.
    pub fn reserve_output(&self, bytes: u64) -> Result<StagingReservation, StagingError> {
        let mut usage = self.shared.usage();
        if usage.attempts >= self.shared.limits.concurrent_attempts {
            return Err(StagingError::AttemptsExhausted);
        }
        usage.reserved_bytes = self.checked_total(&usage, bytes)?;
        usage.attempts += 1;
        drop(usage);
        Ok(self.reservation(bytes, false, true))
    }

    fn checked_total(&self, usage: &StagingUsage, bytes: u64) -> Result<u64, StagingError> {
        usage
            .reserved_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.shared.limits.aggregate_bytes)
            .ok_or(StagingError::AggregateExceeded)
    }

    fn reservation(&self, bytes: u64, queued: bool, attempt: bool) -> StagingReservation {
        StagingReservation {
            shared: Arc::clone(&self.shared),
            bytes,
            queued,
            attempt,
        }
    }
}

/// One held share of the ledger. Dropping it releases every part it still holds.
#[derive(Debug)]
pub struct StagingReservation {
    shared: Arc<Shared>,
    bytes: u64,
    queued: bool,
    attempt: bool,
}

impl StagingReservation {
    /// The reserved byte length.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Release the queued-transfer slot once the input transfer completed.
    ///
    /// The bytes stay reserved while the staged input exists. Repeating the
    /// call has no further effect.
    pub fn finish_transfer(&mut self) {
        if self.queued {
            self.queued = false;
            self.shared.usage().queued_inputs -= 1;
        }
    }

    fn record_leak(&self) {
        self.shared.usage().leaked_files += 1;
    }
}

impl Drop for StagingReservation {
    fn drop(&mut self) {
        let mut usage = self.shared.usage();
        usage.reserved_bytes -= self.bytes;
        usage.queued_inputs -= u64::from(self.queued);
        usage.attempts -= u64::from(self.attempt);
    }
}

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
        reservation: StagingReservation,
    ) -> Result<StagedInput, StagingError> {
        let name = hex_name(name);
        // Clone first, so a failure cannot leave a created file behind.
        self.directory
            .try_clone()
            .map_err(StagingError::from)
            .and_then(|directory| {
                openat2(
                    &self.directory,
                    &name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
                )
                .map(|file| StagedInput {
                    staged: StagedFile {
                        file: File::from(file),
                        directory,
                        name,
                        reservation,
                    },
                    written: 0,
                })
                .map_err(|errno| StagingError::Io(io::Error::from(errno)))
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
    reservation: StagingReservation,
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if unlinkat(&self.directory, &self.name, AtFlags::empty()).is_err() {
            self.reservation.record_leak();
        }
    }
}

/// A staged input still receiving chunks. It is not visible to the adapter.
#[derive(Debug)]
pub struct StagedInput {
    staged: StagedFile,
    written: u64,
}

impl StagedInput {
    /// Append one chunk without ever passing the reserved length.
    ///
    /// # Errors
    /// `ExceedsReservation` when the chunk would pass the declared length.
    pub fn append(&mut self, chunk: &[u8]) -> Result<(), StagingError> {
        let end = u64::try_from(chunk.len())
            .ok()
            .and_then(|length| self.written.checked_add(length))
            .filter(|end| *end <= self.staged.reservation.bytes)
            .ok_or(StagingError::ExceedsReservation)?;
        self.staged
            .file
            .write_all(chunk)
            .map(|()| self.written = end)
            .map_err(StagingError::from)
    }

    /// Complete the transfer once exactly the declared length arrived.
    ///
    /// This releases the queued-transfer slot and keeps the bytes reserved.
    ///
    /// # Errors
    /// `Incomplete` when fewer bytes than declared arrived; the input is then
    /// removed and its reservation released.
    pub fn finish(mut self) -> Result<VerifiedStagedInput, StagingError> {
        if self.written != self.staged.reservation.bytes {
            return Err(StagingError::Incomplete);
        }
        self.staged.reservation.finish_transfer();
        Ok(VerifiedStagedInput {
            staged: self.staged,
        })
    }
}

/// A completely received input; the only form the launch path may read.
#[derive(Debug)]
pub struct VerifiedStagedInput {
    staged: StagedFile,
}

impl VerifiedStagedInput {
    /// The verified byte length.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.staged.reservation.bytes
    }

    /// Whether the verified input is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The staged file, positioned after the last written byte.
    #[must_use]
    pub const fn file(&self) -> &File {
        &self.staged.file
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
        queued_requests: 2,
        concurrent_attempts: 2,
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
    fn input_reservation_is_atomic_and_released_on_drop() -> TestResult {
        let ledger = StagingLedger::new(LIMITS);
        let first = ledger.reserve_input(60)?;
        assert_eq!(first.bytes(), 60);
        assert!(matches!(
            ledger.reserve_input(41),
            Err(StagingError::AggregateExceeded)
        ));
        assert_eq!(ledger.usage().queued_inputs, 1);
        let second = ledger.reserve_input(40)?;
        assert!(matches!(
            ledger.reserve_input(0),
            Err(StagingError::QueueFull)
        ));
        assert_eq!(ledger.usage().reserved_bytes, 100);
        drop(first);
        drop(second);
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn finishing_a_transfer_frees_the_slot_but_keeps_the_bytes_once() -> TestResult {
        let ledger = StagingLedger::new(LIMITS);
        let mut held = ledger.reserve_input(10)?;
        held.finish_transfer();
        held.finish_transfer();
        assert_eq!(ledger.usage().queued_inputs, 0);
        assert_eq!(ledger.usage().reserved_bytes, 10);
        drop(held);
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn output_reservation_counts_attempts_and_the_same_aggregate_cap() -> TestResult {
        let ledger = StagingLedger::new(LIMITS);
        let input = ledger.reserve_input(70)?;
        let output = ledger.reserve_output(30)?;
        assert!(matches!(
            ledger.reserve_output(1),
            Err(StagingError::AggregateExceeded)
        ));
        drop(input);
        let second = ledger.reserve_output(1)?;
        assert!(matches!(
            ledger.reserve_output(0),
            Err(StagingError::AttemptsExhausted)
        ));
        assert_eq!(ledger.usage().attempts, 2);
        drop((output, second));
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn overflowing_and_zero_limits_fail_closed() -> TestResult {
        let ledger = StagingLedger::new(LIMITS);
        let held = ledger.reserve_input(1)?;
        assert!(matches!(
            ledger.reserve_output(u64::MAX),
            Err(StagingError::AggregateExceeded)
        ));
        drop(held);
        let closed = StagingLedger::new(StagingLimits {
            aggregate_bytes: 0,
            queued_requests: 0,
            concurrent_attempts: 0,
        });
        assert!(matches!(
            closed.reserve_input(0),
            Err(StagingError::QueueFull)
        ));
        assert!(matches!(
            closed.reserve_output(0),
            Err(StagingError::AttemptsExhausted)
        ));
        Ok(())
    }

    #[test]
    fn a_panic_while_counting_does_not_wedge_the_ledger() -> TestResult {
        let ledger = StagingLedger::new(LIMITS);
        let clone = ledger.clone();
        let outcome = std::thread::spawn(move || {
            let _guard = clone.shared.usage.lock();
            std::panic::resume_unwind(Box::new("poison"));
        })
        .join();
        assert!(outcome.is_err());
        let held = ledger.reserve_input(5)?;
        drop(held);
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn staged_input_is_visible_only_after_complete_verification() -> TestResult {
        let (temporary, staging) = directory()?;
        let ledger = StagingLedger::new(LIMITS);
        let mut input = staging.create_input([0xab; 16], ledger.reserve_input(5)?)?;
        input.append(b"abc")?;
        assert!(matches!(
            input.append(b"def"),
            Err(StagingError::ExceedsReservation)
        ));
        input.append(b"de")?;
        let name = "ab".repeat(16);
        let path = temporary.path().join(&name);
        assert_eq!(fs::metadata(&path)?.mode() & 0o7777, 0o600);
        let verified = input.finish()?;
        assert_eq!(verified.len(), 5);
        assert!(!verified.is_empty());
        assert_eq!(fs::read(&path)?, b"abcde");
        assert_eq!(verified.file().metadata()?.len(), 5);
        assert_eq!(ledger.usage().queued_inputs, 0);
        assert_eq!(ledger.usage().reserved_bytes, 5);
        drop(verified);
        assert!(!path.exists());
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn an_incomplete_or_abandoned_input_is_removed_and_released() -> TestResult {
        let (temporary, staging) = directory()?;
        let ledger = StagingLedger::new(LIMITS);
        let mut input = staging.create_input([1; 16], ledger.reserve_input(4)?)?;
        input.append(b"ab")?;
        assert!(matches!(input.finish(), Err(StagingError::Incomplete)));
        assert_eq!(fs::read_dir(temporary.path())?.count(), 0);
        assert_eq!(ledger.usage(), StagingUsage::default());
        let empty = staging
            .create_input([2; 16], ledger.reserve_input(0)?)?
            .finish()?;
        assert!(empty.is_empty());
        Ok(())
    }

    #[test]
    fn creation_never_adopts_an_existing_entry_or_follows_a_symlink() -> TestResult {
        let (temporary, staging) = directory()?;
        let ledger = StagingLedger::new(LIMITS);
        let outside = tempfile::tempdir()?;
        let target = outside.path().join("victim");
        symlink(&target, temporary.path().join("01".repeat(16)))?;
        let result = staging.create_input([1; 16], ledger.reserve_input(1)?);
        assert!(matches!(result, Err(StagingError::Io(_))));
        assert!(!target.exists());
        fs::write(temporary.path().join("02".repeat(16)), b"x")?;
        assert!(staging
            .create_input([2; 16], ledger.reserve_input(1)?)
            .is_err());
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn a_file_removed_underneath_is_counted_as_leaked() -> TestResult {
        let (temporary, staging) = directory()?;
        let ledger = StagingLedger::new(LIMITS);
        let input = staging.create_input([3; 16], ledger.reserve_input(1)?)?;
        let held = Arc::clone(&input.staged.reservation.shared);
        fs::remove_file(temporary.path().join("03".repeat(16)))?;
        drop(input);
        assert_eq!(held.usage().leaked_files, 1);
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
