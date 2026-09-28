//! Read-only, exclusively owned inventory for unfinished registry transitions.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use rustix::fs::{openat2, Dir, Mode, OFlags, ResolveFlags};

use super::{
    registry_io, validate_directory, PlannedAttemptIntent, RegistryDirectory,
    SystemdAttemptRegistryError, TransientServiceUnitName,
};

type RegistryResult<T> = Result<T, SystemdAttemptRegistryError>;
const MAX_RECORD_SIZE: usize = 84;

/// A complete recorded intent observed during recovery, not activation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredAttemptIntent {
    planned: PlannedAttemptIntent,
    directory_identities: Option<[(u64, u64); 2]>,
}

impl RecoveredAttemptIntent {
    /// The recorded attempt and admitted SIM1 identities.
    #[must_use]
    pub const fn planned(&self) -> &PlannedAttemptIntent {
        &self.planned
    }

    /// Recorded `(device, inode)` pairs, in attempt-directory then root order.
    ///
    /// These are recorded claims; cleanup must independently correlate them
    /// with held directories and any mount, unit, cgroup, loop and dm resources.
    #[must_use]
    pub const fn directory_identities(&self) -> Option<[(u64, u64); 2]> {
        self.directory_identities
    }

    fn decode(bytes: &[u8]) -> RegistryResult<Self> {
        let mut planned_bytes = [0; 52];
        planned_bytes.copy_from_slice(&bytes[..52]);
        planned_bytes[..4].copy_from_slice(b"PAI1");
        let planned = PlannedAttemptIntent::decode(&planned_bytes)?;
        let directory_identities = if bytes.len() == MAX_RECORD_SIZE {
            let mut identities = [0; 4];
            for (slot, chunk) in identities.iter_mut().zip(bytes[52..].chunks_exact(8)) {
                let mut word = [0; 8];
                word.copy_from_slice(chunk);
                *slot = u64::from_le_bytes(word);
            }
            if identities[0] != identities[2] || identities[1] == identities[3] {
                return Err(SystemdAttemptRegistryError::InvalidIntent);
            }
            Some([
                (identities[0], identities[1]),
                (identities[2], identities[3]),
            ])
        } else {
            None
        };
        Ok(Self {
            planned,
            directory_identities,
        })
    }
}

/// One retained observation of a committed key or recognizable interrupted write.
#[derive(Debug)]
pub struct RegistryRecoveryEntry {
    // Retain the original inode so replacement cannot reuse its identity.
    _file: File,
    observation: RegistryEntryObservation,
}

#[derive(Debug, Eq, PartialEq)]
struct RegistryEntryObservation {
    name: String,
    attempt_id: [u8; 16],
    temporary: bool,
    intent: Option<RecoveredAttemptIntent>,
    device: u64,
    inode: u64,
    bytes: Vec<u8>,
}

impl RegistryRecoveryEntry {
    /// Exact validated registry component, not a caller-supplied path.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.observation.name
    }

    /// The nonzero identity derived from the canonical filename.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.observation.attempt_id
    }

    /// Whether this is an unpublished temporary write.
    #[must_use]
    pub const fn is_temporary(&self) -> bool {
        self.observation.temporary
    }

    /// Complete recorded intent, or `None` for an interrupted partial write.
    #[must_use]
    pub const fn intent(&self) -> Option<&RecoveredAttemptIntent> {
        self.observation.intent.as_ref()
    }
}

/// Exclusive startup inventory which cannot commit, delete, or reopen admission.
///
/// Holding this object keeps the registry lock. It inventories registry files
/// only; the recovery owner must still inventory units and attempt resources,
/// prove ownership/absence, and complete durable cleanup before admitting work.
#[derive(Debug)]
pub struct SystemdAttemptRecovery {
    directory: RegistryDirectory,
    entries: Vec<RegistryRecoveryEntry>,
}

impl SystemdAttemptRecovery {
    /// Open and inventory the fixed root-owned registry while admission is closed.
    ///
    /// # Errors
    /// Rejects unsafe paths, another live owner, unknown filenames or record
    /// stages, unsafe metadata, mismatched identities and oversized files.
    pub fn open() -> Result<Self, SystemdAttemptRegistryError> {
        Self::from_directory(RegistryDirectory::open()?)
    }

    fn from_directory(directory: RegistryDirectory) -> RegistryResult<Self> {
        inventory(&directory).map(|entries| Self { directory, entries })
    }

    /// Sorted observations; none is proof that associated resources are absent.
    #[must_use]
    pub fn entries(&self) -> &[RegistryRecoveryEntry] {
        &self.entries
    }

    /// Repeat the inventory and require exact names, identities and record bytes.
    ///
    /// # Errors
    /// Rejects additions, removals, inode substitution, metadata changes or
    /// changed contents. Recovery must stop on any contradiction.
    pub fn verify_unchanged(&self) -> Result<(), SystemdAttemptRegistryError> {
        if inventory(&self.directory)?
            .iter()
            .map(|entry| &entry.observation)
            .eq(self.entries.iter().map(|entry| &entry.observation))
        {
            Ok(())
        } else {
            Err(SystemdAttemptRegistryError::ReconciliationRequired)
        }
    }
}

fn inventory(directory: &RegistryDirectory) -> RegistryResult<Vec<RegistryRecoveryEntry>> {
    validate_directory(&directory.runtime, directory.owner, true)?;
    validate_directory(&directory.file, directory.owner, true)?;
    let mut entries = Vec::new();
    for item in registry_io(|| Dir::read_from(&directory.file).map_err(std::io::Error::from))? {
        let item = registry_io(|| item.map_err(std::io::Error::from))?;
        let name = item
            .file_name()
            .to_str()
            .map_err(|_| SystemdAttemptRegistryError::InvalidIntent)?;
        if name != "." && name != ".." {
            entries.push(read_entry(directory, name)?);
        }
    }
    entries.sort_unstable_by(|a, b| a.component().cmp(b.component()));
    Ok(entries)
}

fn read_entry(directory: &RegistryDirectory, name: &str) -> RegistryResult<RegistryRecoveryEntry> {
    let (attempt_id, temporary) = parse_name(name)?;
    let file = File::from(registry_io(|| {
        openat2(
            &directory.file,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(std::io::Error::from)
    })?);
    let metadata = registry_io(|| file.metadata())?;
    if !metadata.is_file()
        || metadata.uid() != directory.owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > MAX_RECORD_SIZE as u64
    {
        return Err(SystemdAttemptRegistryError::UnsafeRegistry);
    }
    let bytes = read_record_content(&file, metadata.len())?;
    let intent = parse_content(&bytes, attempt_id, temporary)?;
    Ok(RegistryRecoveryEntry {
        _file: file,
        observation: RegistryEntryObservation {
            name: name.to_owned(),
            attempt_id,
            temporary,
            intent,
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes,
        },
    })
}

// Each inventory entry was independently opened at offset zero. Read at most
// one byte beyond the format bound and compare with its metadata snapshot, so
// growth or truncation between metadata and read cannot produce an observation.
fn read_record_content(file: &File, expected_length: u64) -> RegistryResult<Vec<u8>> {
    let mut bytes = Vec::new();
    registry_io(|| {
        file.take(MAX_RECORD_SIZE as u64 + 1)
            .read_to_end(&mut bytes)
    })?;
    if bytes.len() as u64 != expected_length {
        return Err(SystemdAttemptRegistryError::ReconciliationRequired);
    }
    Ok(bytes)
}

fn parse_name(name: &str) -> RegistryResult<([u8; 16], bool)> {
    let (component, temporary) = if let Some(rest) = name.strip_prefix(".planned-") {
        let (component, suffix) = rest
            .split_once('-')
            .ok_or(SystemdAttemptRegistryError::InvalidIntent)?;
        let (process, sequence) = suffix
            .split_once('-')
            .ok_or(SystemdAttemptRegistryError::InvalidIntent)?;
        if !canonical_positive::<u32>(process) || !canonical_positive::<u64>(sequence) {
            return Err(SystemdAttemptRegistryError::InvalidIntent);
        }
        (component, true)
    } else {
        (name, false)
    };
    if component.len() != 32 || !component.is_ascii() {
        return Err(SystemdAttemptRegistryError::InvalidIntent);
    }
    let mut attempt_id = [0; 16];
    for (index, slot) in attempt_id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&component[index * 2..index * 2 + 2], 16)
            .map_err(|_| SystemdAttemptRegistryError::InvalidIntent)?;
    }
    let unit = TransientServiceUnitName::from_attempt_id(attempt_id)
        .map_err(|_| SystemdAttemptRegistryError::InvalidIntent)?;
    if unit.attempt_component() != component {
        return Err(SystemdAttemptRegistryError::InvalidIntent);
    }
    Ok((attempt_id, temporary))
}

fn canonical_positive<T: std::str::FromStr + std::fmt::Display>(text: &str) -> bool {
    !text.starts_with('0')
        && text
            .parse::<T>()
            .is_ok_and(|value| value.to_string() == text)
}

fn parse_content(
    bytes: &[u8],
    attempt_id: [u8; 16],
    temporary: bool,
) -> RegistryResult<Option<RecoveredAttemptIntent>> {
    let header = &bytes[..bytes.len().min(4)];
    let size = if b"PAI1".starts_with(header) {
        52
    } else if b"PAI2".starts_with(header) {
        84
    } else {
        return Err(SystemdAttemptRegistryError::InvalidIntent);
    };
    if bytes.len() > size || !temporary && bytes.len() != size {
        return Err(SystemdAttemptRegistryError::InvalidIntent);
    }
    validate_record_prefix(bytes, attempt_id)?;
    if bytes.len() == size {
        RecoveredAttemptIntent::decode(bytes).map(Some)
    } else {
        Ok(None)
    }
}

fn validate_record_prefix(bytes: &[u8], attempt_id: [u8; 16]) -> RegistryResult<()> {
    let available_id = bytes.get(4..).unwrap_or_default();
    let id_length = available_id.len().min(16);
    let root_device = bytes.get(68..).unwrap_or_default();
    let device_length = root_device.len().min(8);
    if available_id[..id_length] != attempt_id[..id_length]
        || bytes.get(20..52).is_some_and(|digest| digest == [0; 32])
        || device_length > 0 && root_device[..device_length] != bytes[52..52 + device_length]
    {
        return Err(SystemdAttemptRegistryError::InvalidIntent);
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::tests::with_io_fault;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;
    use crate::SystemdAttemptRegistry;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    const KEY: &str = "01010101010101010101010101010101";

    fn fixture() -> TestResult<(tempfile::TempDir, RegistryDirectory)> {
        let (directory, runtime, owner) = super::super::tests::fixture()?;
        let held = RegistryDirectory::from_runtime_directory(&runtime, owner)?;
        Ok((directory, held))
    }

    fn planned() -> TestResult<Vec<u8>> {
        Ok(PlannedAttemptIntent::new([1; 16], [2; 32])?
            .encode()
            .to_vec())
    }

    fn directory_record() -> TestResult<Vec<u8>> {
        let mut bytes = planned()?;
        bytes[..4].copy_from_slice(b"PAI2");
        for value in [7_u64, 11, 7, 13] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(bytes)
    }

    fn write_record(root: &std::path::Path, name: &str, bytes: &[u8]) -> TestResult {
        let path = root.join("registry").join(name);
        fs::write(&path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[test]
    fn record_read_rejects_growth_and_truncation_since_metadata_snapshot() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("record");
        let original = planned()?;
        fs::write(&path, &original)?;
        let expected_length = fs::metadata(&path)?.len();
        for contents in [original[..51].to_vec(), vec![0; MAX_RECORD_SIZE + 2]] {
            fs::write(&path, contents)?;
            let file = File::open(&path)?;
            assert!(matches!(
                read_record_content(&file, expected_length),
                Err(SystemdAttemptRegistryError::ReconciliationRequired)
            ));
        }
        Ok(())
    }

    #[test]
    fn complete_record_decoder_independently_rejects_invalid_planned_identity() -> TestResult {
        for range in [4..20, 20..52] {
            let mut bytes = planned()?;
            bytes[range].fill(0);
            assert!(RecoveredAttemptIntent::decode(&bytes).is_err());
        }
        Ok(())
    }

    #[test]
    fn fixed_public_recovery_inventories_both_durable_stages() -> TestResult {
        if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_none() {
            let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/run-isolated-test.sh");
            let output = std::process::Command::new(runner).arg(std::env::current_exe()?)
                .arg("attempt_registry::recovery::tests::fixed_public_recovery_inventories_both_durable_stages")
                .output()?;
            assert!(
                output.status.success(),
                "isolated recovery test failed: {:?}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }
        assert!(!std::path::Path::new("/run/pigloros").exists());
        assert!(SystemdAttemptRecovery::open().is_err());
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
        drop(registry.commit_planned(&PlannedAttemptIntent::new([1; 16], [2; 32])?)?);
        drop(
            registry
                .commit_planned(&PlannedAttemptIntent::new([2; 16], [2; 32])?)?
                .prepare_directory()?,
        );
        assert!(SystemdAttemptRecovery::open().is_err());
        drop(registry);
        let (opened, operation_count) = with_io_fault(None, SystemdAttemptRecovery::open);
        drop(opened?);
        assert!(operation_count > 0);
        for fail_at in 0..operation_count {
            let (result, observed) = with_io_fault(Some(fail_at), SystemdAttemptRecovery::open);
            assert!(matches!(result, Err(SystemdAttemptRegistryError::Io(_))));
            assert_eq!(observed, fail_at + 1);
            assert_eq!(fs::read_dir("/run/pigloros/sandbox/registry")?.count(), 2);
        }
        let recovery = SystemdAttemptRecovery::open()?;
        assert_eq!(recovery.entries().len(), 2);
        assert_eq!(recovery.entries()[0].attempt_id(), [1; 16]);
        assert!(!recovery.entries()[0].is_temporary());
        assert!(recovery.entries()[0]
            .intent()
            .ok_or("missing plan")?
            .directory_identities()
            .is_none());
        let recorded = recovery.entries()[1]
            .intent()
            .ok_or("missing directory stage")?;
        assert_eq!(recorded.planned().attempt_id(), [2; 16]);
        assert_eq!(recorded.planned().sim1_digest(), [2; 32]);
        assert!(recorded.directory_identities().is_some());
        recovery.verify_unchanged()?;
        assert!(SystemdAttemptRecovery::open().is_err());
        assert!(SystemdAttemptRegistry::open().is_err());
        drop(recovery);
        assert!(SystemdAttemptRegistry::open().is_err());
        SystemdAttemptRecovery::open()?.verify_unchanged()?;
        Ok(())
    }

    #[test]
    fn recognizes_every_interrupted_record_prefix_without_authorizing_cleanup() -> TestResult {
        for bytes in [planned()?, directory_record()?] {
            for length in 0..=bytes.len() {
                let (directory, held) = fixture()?;
                let name = format!(".planned-{KEY}-123-1");
                write_record(directory.path(), &name, &bytes[..length])?;
                let recovery = SystemdAttemptRecovery::from_directory(held)?;
                let entry = &recovery.entries()[0];
                assert_eq!(entry.component(), name);
                assert_eq!(entry.attempt_id(), [1; 16]);
                assert!(entry.is_temporary());
                assert_eq!(entry.intent().is_some(), length == bytes.len());
                recovery.verify_unchanged()?;
            }
        }
        Ok(())
    }

    #[test]
    fn recovery_readback_io_boundary_failures_preserve_locked_inventory() -> TestResult {
        let (directory, held) = fixture()?;
        let before = planned()?;
        write_record(directory.path(), KEY, &before)?;
        let recovery = SystemdAttemptRecovery::from_directory(held)?;
        let (result, count) = with_io_fault(None, || recovery.verify_unchanged());
        result?;
        assert!(count > 0);
        for fail_at in 0..count {
            let (result, observed) = with_io_fault(Some(fail_at), || recovery.verify_unchanged());
            assert!(matches!(result, Err(SystemdAttemptRegistryError::Io(_))));
            assert_eq!(observed, fail_at + 1);
            assert_eq!(recovery.entries().len(), 1);
            assert_eq!(recovery.entries()[0].component(), KEY);
            assert_eq!(
                fs::read(directory.path().join("registry").join(KEY))?,
                before
            );
            let runtime = File::open(directory.path())?;
            assert!(
                RegistryDirectory::from_runtime_directory(&runtime, runtime.metadata()?.uid())
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn incomplete_records_reject_every_known_identity_contradiction() -> TestResult {
        let name = format!(".planned-{KEY}-123-1");
        for length in 5..20 {
            let (directory, held) = fixture()?;
            let mut bytes = planned()?;
            bytes[length - 1] ^= 1;
            write_record(directory.path(), &name, &bytes[..length])?;
            assert!(SystemdAttemptRecovery::from_directory(held).is_err());
        }
        for length in 52..84 {
            let (directory, held) = fixture()?;
            let mut bytes = directory_record()?;
            bytes[20..52].fill(0);
            write_record(directory.path(), &name, &bytes[..length])?;
            assert!(SystemdAttemptRecovery::from_directory(held).is_err());
        }
        for length in 69..84 {
            let (directory, held) = fixture()?;
            let mut bytes = directory_record()?;
            bytes[length.min(76) - 1] ^= 1;
            write_record(directory.path(), &name, &bytes[..length])?;
            assert!(SystemdAttemptRecovery::from_directory(held).is_err());
        }
        Ok(())
    }

    #[test]
    fn exact_stage_identity_and_sorted_eight_attempt_inventory() -> TestResult {
        let (directory, held) = fixture()?;
        for id in (1..=8).rev() {
            let plan = PlannedAttemptIntent::new([id; 16], [2; 32])?;
            write_record(
                directory.path(),
                plan.unit_name().attempt_component(),
                &plan.encode(),
            )?;
        }
        let recovery = SystemdAttemptRecovery::from_directory(held)?;
        assert_eq!(recovery.entries().len(), 8);
        for (entry, id) in recovery.entries().iter().zip(1..=8) {
            assert_eq!(
                entry
                    .intent()
                    .ok_or("missing intent")?
                    .planned()
                    .attempt_id(),
                [id; 16]
            );
        }
        recovery.verify_unchanged()?;
        let decoded =
            parse_content(&directory_record()?, [1; 16], false)?.ok_or("missing directory")?;
        assert_eq!(decoded.directory_identities(), Some([(7, 11), (7, 13)]));
        Ok(())
    }

    #[test]
    fn unknown_noncanonical_names_and_record_shapes_are_rejected() -> TestResult {
        for name in [
            "unknown".to_owned(),
            "0".repeat(32),
            "AB".repeat(16),
            "gh".repeat(16),
            "é".repeat(16),
            format!(".planned-{KEY}"),
            format!(".planned-{KEY}-1"),
            format!(".planned-{KEY}-0-1"),
            format!(".planned-{KEY}-01-1"),
            format!(".planned-{KEY}-4294967296-1"),
            format!(".planned-{KEY}-1-0"),
            format!(".planned-{KEY}-1-01"),
            format!(".planned-{KEY}-1-18446744073709551616"),
            format!(".planned-{KEY}-1-1-extra"),
        ] {
            let (directory, held) = fixture()?;
            write_record(directory.path(), &name, &planned()?)?;
            assert!(
                SystemdAttemptRecovery::from_directory(held).is_err(),
                "accepted {name}"
            );
        }
        for fault in 0..8 {
            let (directory, held) = fixture()?;
            let mut bytes = directory_record()?;
            match fault {
                0 => bytes[3] = b'9',
                1 => bytes.truncate(51),
                2 => bytes[4] ^= 1,
                3 => bytes[20..52].fill(0),
                4 => bytes[68..76].copy_from_slice(&8_u64.to_le_bytes()),
                5 => bytes[76..84].copy_from_slice(&11_u64.to_le_bytes()),
                6 => bytes.push(0),
                _ => bytes[..4].copy_from_slice(b"PAI1"),
            }
            write_record(directory.path(), KEY, &bytes)?;
            assert!(SystemdAttemptRecovery::from_directory(held).is_err());
        }
        Ok(())
    }

    #[test]
    fn unsafe_record_metadata_is_rejected() -> TestResult {
        for fault in 0..5 {
            let (directory, mut held) = fixture()?;
            let path = directory.path().join("registry").join(KEY);
            write_record(directory.path(), KEY, &planned()?)?;
            match fault {
                0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?,
                1 => fs::hard_link(&path, directory.path().join("alias"))?,
                2 => {
                    fs::remove_file(&path)?;
                    fs::create_dir(&path)?;
                }
                3 => {
                    fs::remove_file(&path)?;
                    symlink("missing", &path)?;
                }
                _ => held.owner ^= 1,
            }
            // Wrong-owner injection directly exercises file ownership without
            // first rejecting the deliberately mismatched runtime directory.
            assert!(read_entry(&held, KEY).is_err());
        }
        Ok(())
    }

    #[test]
    fn changed_inventory_and_inode_replacement_are_detected() -> TestResult {
        for fault in 0..4 {
            let (directory, held) = fixture()?;
            write_record(directory.path(), KEY, &planned()?)?;
            let recovery = SystemdAttemptRecovery::from_directory(held)?;
            let path = directory.path().join("registry").join(KEY);
            match fault {
                0 => fs::remove_file(&path)?,
                1 => {
                    fs::remove_file(&path)?;
                    write_record(directory.path(), KEY, &planned()?)?;
                }
                2 => {
                    let mut bytes = planned()?;
                    bytes[20] = 3;
                    write_record(directory.path(), KEY, &bytes)?;
                }
                _ => write_record(directory.path(), &format!(".planned-{KEY}-1-1"), b"PAI")?,
            }
            assert!(recovery.verify_unchanged().is_err());
        }
        let (_directory, held) = fixture()?;
        let recovery = SystemdAttemptRecovery::from_directory(held)?;
        assert!(recovery.entries().is_empty());
        recovery.verify_unchanged()?;
        Ok(())
    }
}
