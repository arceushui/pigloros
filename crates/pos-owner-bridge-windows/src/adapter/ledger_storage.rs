#![cfg(windows)]
#![cfg(any(test, feature = "test-support"))]
#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf, Prefix};

use pos_owner_bridge::{BridgeError, UnavailableCode};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
};

use super::nonce_ledger::WindowsSubjectEncryptorLock;

const LIMIT: usize = 1_048_576;
const LEDGER: &str = "subject-nonce-ledger.v1";
const TEMPORARY: &str = "subject-nonce-ledger.v1.tmp";
const SHARE_ALL: u32 = 7;
const REPARSE_POINT: u32 = 0x400;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CommitStage {
    Created,
    Written,
    FileSynced,
    DirectoryChecked,
    LedgerChecked,
    TemporaryChecked,
    Renamed,
    ReadBack,
}

/// Bounded raw ledger storage tied to a held test-support mutex.
///
/// Bytes remain untrusted: this seam does not parse SNL1, establish an owner or
/// store binding, initialize a registered identity, or reserve an IV.
pub struct WindowsNonceLedger<'guard> {
    _guard: &'guard WindowsSubjectEncryptorLock,
    directory: File,
    path: PathBuf,
    volume: u32,
}

impl WindowsSubjectEncryptorLock {
    /// Open the private NTFS ledger directory for bounded test-support storage.
    ///
    /// # Errors
    /// Refuses unsafe paths, directory security, volumes, stale staging files,
    /// identity changes, or I/O failures. It never creates a ledger file.
    pub fn open_nonce_ledger(&self) -> Result<WindowsNonceLedger<'_>, BridgeError> {
        WindowsNonceLedger::open(self).map_err(|()| unavailable())
    }
}

impl<'guard> WindowsNonceLedger<'guard> {
    fn open(guard: &'guard WindowsSubjectEncryptorLock) -> Result<Self, ()> {
        let path = guard.test_directory.join("PiglorOS");
        require_dos_path(&path)
            .and_then(|()| admit_or_create_directory(&path).ok().ok_or(()))
            .and_then(|()| crate::Native::cleanup_path_ntfs(&path))
            .and_then(|()| open_directory(&path))
            .and_then(|directory| {
                crate::Native::cleanup_file_volume(&directory).map(|volume| (directory, volume))
            })
            .and_then(|(directory, volume)| {
                let store = Self {
                    _guard: guard,
                    directory,
                    path,
                    volume,
                };
                store
                    .admit_directory()
                    .and_then(|()| store.remove_stale_temporary())
                    .map(|()| store)
            })
    }

    /// Read bounded raw bytes from an existing ledger file.
    ///
    /// # Errors
    /// Refuses missing, unsafe, oversized or unreadable state without returning
    /// partial bytes or releasing the mutex.
    pub fn read_nonce_ledger_bytes(&self) -> Result<Vec<u8>, BridgeError> {
        self.read().map_err(|()| unavailable())
    }

    fn read(&self) -> Result<Vec<u8>, ()> {
        self.admit_directory()
            .and_then(|()| self.open_existing(LEDGER))
            .and_then(read_bounded)
    }

    /// Replace an existing ledger with bounded raw bytes.
    ///
    /// # Errors
    /// Refuses missing or unsafe state, contention and I/O errors. An error
    /// after replacement has an unconfirmed outcome; the caller must not use a
    /// candidate nonce or restore a previous counter on that error.
    pub fn replace_nonce_ledger_bytes(&self, bytes: &[u8]) -> Result<(), BridgeError> {
        self.replace(bytes).map_err(|()| unavailable())
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), ()> {
        self.replace_observing(bytes, |_| Ok(()))
    }

    fn replace_observing(
        &self,
        bytes: &[u8],
        mut after: impl FnMut(CommitStage) -> Result<(), ()>,
    ) -> Result<(), ()> {
        if bytes.len() > LIMIT {
            return Err(());
        }
        let ledger_path = self.path.join(LEDGER);
        let temporary_path = self.path.join(TEMPORARY);
        self.admit_directory()
            .and_then(|()| self.open_existing(LEDGER))
            .and_then(|previous| {
                // Both handles stay open across the rechecks and close before
                // the move, whether this closure succeeds or refuses.
                crate::Native::create_private_ledger_file(&temporary_path)
                    .and_then(|temporary| {
                        self.validate_file(&temporary, &temporary_path)
                            .map(|()| temporary)
                    })
                    .and_then(|temporary| after(CommitStage::Created).map(|()| temporary))
                    .and_then(|mut temporary| {
                        temporary
                            .write_all(bytes)
                            .ok()
                            .ok_or(())
                            .map(|()| temporary)
                    })
                    .and_then(|temporary| after(CommitStage::Written).map(|()| temporary))
                    .and_then(|temporary| temporary.sync_all().ok().ok_or(()).map(|()| temporary))
                    .and_then(|temporary| after(CommitStage::FileSynced).map(|()| temporary))
                    .and_then(|temporary| {
                        self.admit_directory()
                            .and_then(|()| after(CommitStage::DirectoryChecked))
                            .and_then(|()| Self::same_name(&previous, &ledger_path))
                            .and_then(|()| after(CommitStage::LedgerChecked))
                            .and_then(|()| Self::same_name(&temporary, &temporary_path))
                            .and_then(|()| after(CommitStage::TemporaryChecked))
                    })
            })
            .and_then(|()| crate::Native::replace_ledger(&temporary_path, &ledger_path))
            .and_then(|()| after(CommitStage::Renamed))
            .and_then(|()| self.admit_directory())
            .and_then(|()| self.open_existing(LEDGER))
            .and_then(read_bounded)
            .and_then(|observed| if observed == bytes { Ok(()) } else { Err(()) })
            .and_then(|()| after(CommitStage::ReadBack))
    }

    fn admit_directory(&self) -> Result<(), ()> {
        crate::verify_private_directory(&self.path)
            .ok()
            .ok_or(())
            .and_then(|()| crate::Native::cleanup_file_volume(&self.directory))
            .and_then(|volume| (volume == self.volume).then_some(()).ok_or(()))
            .and_then(|()| open_directory(&self.path))
            .and_then(|reopened| same_identity(&self.directory, &reopened))
    }

    fn validate_file(&self, file: &File, path: &Path) -> Result<(), ()> {
        file.metadata()
            .ok()
            .ok_or(())
            .and_then(|metadata| {
                (metadata.is_file() && metadata.file_attributes() & REPARSE_POINT == 0)
                    .then_some(())
                    .ok_or(())
            })
            .and_then(|()| crate::Native::require_private_file(file))
            .and_then(|()| crate::Native::file_link_count(file))
            .and_then(|links| (links == 1).then_some(()).ok_or(()))
            .and_then(|()| crate::Native::cleanup_file_volume(file))
            .and_then(|volume| (volume == self.volume).then_some(()).ok_or(()))
            .and_then(|()| Self::same_name(file, path))
    }

    fn same_name(file: &File, path: &Path) -> Result<(), ()> {
        open_file(path).and_then(|reopened| same_identity(file, &reopened))
    }

    fn open_existing(&self, name: &str) -> Result<File, ()> {
        let path = self.path.join(name);
        open_file(&path).and_then(|file| self.validate_file(&file, &path).map(|()| file))
    }

    fn remove_stale_temporary(&self) -> Result<(), ()> {
        let path = self.path.join(TEMPORARY);
        // An unreadable slot takes the same guarded recovery as a present
        // one: nothing is removed unless every recovery check admits it.
        if is_absent(&path) {
            Ok(())
        } else {
            self.recover_stale_temporary(&path)
        }
    }

    fn recover_stale_temporary(&self, path: &Path) -> Result<(), ()> {
        self.open_existing(LEDGER)
            .and_then(|primary| {
                self.open_existing(TEMPORARY)
                    .map(|temporary| (primary, temporary))
            })
            .and_then(|(primary, temporary)| {
                // Both handles close before the removal below.
                read_bounded_copy(&primary)
                    .and_then(|_primary_bytes| read_bounded_copy(&temporary))
                    .and_then(|_temporary_bytes| self.admit_directory())
                    .and_then(|()| Self::same_name(&primary, &self.path.join(LEDGER)))
                    .and_then(|()| Self::same_name(&temporary, path))
            })
            .and_then(|()| fs::remove_file(path).ok().ok_or(()))
    }
}

/// Admit an existing private directory, or create it when it is absent.
///
/// Any other observation is left to the verification, which admits nothing
/// but an existing private directory.
fn admit_or_create_directory(path: &Path) -> Result<(), BridgeError> {
    if is_absent(path) {
        crate::create_private_directory(path)
    } else {
        crate::verify_private_directory(path)
    }
}

fn is_absent(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn open_directory(path: &Path) -> Result<File, ()> {
    OpenOptions::new()
        .read(true)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .ok()
        .ok_or(())
}

fn require_dos_path(path: &Path) -> Result<(), ()> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        || components.next() != Some(Component::RootDir)
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(());
    }
    Ok(())
}

fn open_file(path: &Path) -> Result<File, ()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_WRITE_THROUGH.0)
        .open(path)
        .ok()
        .ok_or(())
}

fn same_identity(left: &File, right: &File) -> Result<(), ()> {
    crate::Native::file_identity(left)
        .and_then(|first| crate::Native::file_identity(right).map(|second| first == second))
        .and_then(|same| same.then_some(()).ok_or(()))
}

fn read_bounded(file: File) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    let read = file
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()
        .ok_or(());
    read.and(if bytes.len() > LIMIT {
        Err(())
    } else {
        Ok(bytes)
    })
}

fn read_bounded_copy(file: &File) -> Result<Vec<u8>, ()> {
    file.try_clone().ok().ok_or(()).and_then(read_bounded)
}

const fn unavailable() -> BridgeError {
    BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable)
}

#[cfg(test)]
impl crate::Native {
    pub(crate) fn exercise_ledger_storage() {
        native_tests::exercise();
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::symlink_file;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use pos_crypto::subject_key::SubjectKeyUseV1;
    use pos_crypto::subject_nonce_ledger::{
        SubjectNonceLedgerErrorV1, SubjectNonceLedgerRowV1, SubjectNonceLedgerV1,
        SubjectStoreFileIdV1,
    };

    use super::super::nonce_ledger::Probe;
    use crate::adapter::native_tests::pass;

    const PROBE: &str = "PIGLOROS_WINDOWS_NONCE_STORAGE_PROBE";
    const CONTROL: &str = "PIGLOROS_WINDOWS_NONCE_STORAGE_CONTROL";
    const BASE: &str = "PIGLOROS_WINDOWS_NONCE_STORAGE_BASE";
    const MARKER: &str = "PIGLOROS_WINDOWS_NONCE_STORAGE_MARKER";
    const STAGES: [(&str, CommitStage); 8] = [
        ("created", CommitStage::Created),
        ("written", CommitStage::Written),
        ("synced", CommitStage::FileSynced),
        ("directory-checked", CommitStage::DirectoryChecked),
        ("ledger-checked", CommitStage::LedgerChecked),
        ("temporary-checked", CommitStage::TemporaryChecked),
        ("renamed", CommitStage::Renamed),
        ("readback", CommitStage::ReadBack),
    ];

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }

    pub(super) fn exercise() {
        let _serial = pass(super::super::nonce_ledger::NONCE_TEST_LOCK.lock());
        if let Ok(requested) = std::env::var(PROBE) {
            run_probe(&requested);
            return;
        }
        let base = std::env::temp_dir().join(format!(
            "piglor-nonce-ledger-{}-{}",
            std::process::id(),
            pass(SystemTime::now().duration_since(UNIX_EPOCH)).as_nanos()
        ));
        pass(fs::create_dir(&base));
        let fixture = Fixture(base);
        raw_boundaries(&fixture.0);
        crash_stages(&fixture.0);
        checked_fixture(&fixture.0);
    }

    fn run_probe(requested: &str) {
        let base = PathBuf::from(pass(std::env::var_os(BASE).ok_or("missing probe base")));
        let marker = PathBuf::from(pass(std::env::var_os(MARKER).ok_or("missing probe marker")));
        let selected = pass(
            STAGES
                .iter()
                .find_map(|(name, stage)| (*name == requested).then_some(*stage))
                .ok_or("unknown probe stage"),
        );
        let guard = pass(WindowsSubjectEncryptorLock::acquire(&base));
        let ledger = pass(guard.open_nonce_ledger());
        let control = std::env::var_os(CONTROL).is_some();
        let mut saw_eof = false;
        let result = ledger.replace_observing(b"candidate", |stage| {
            if stage == selected {
                pass(fs::write(&marker, requested.as_bytes()));
                let mut line = String::new();
                saw_eof = pass(io::stdin().read_line(&mut line)) == 0;
                return Err(());
            }
            Ok(())
        });
        assert!(
            control && saw_eof && result == Err(()),
            "storage probe returned without interruption"
        );
    }

    fn raw_boundaries(base: &Path) {
        assert_path_admission();
        let guard = pass(WindowsSubjectEncryptorLock::acquire(base));
        let mut ledger = pass(guard.open_nonce_ledger());
        let path = base.join("PiglorOS").join(LEDGER);
        recovery_requires_admitted_primary(&guard, base, &path);
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(b"missing"),
            Err(unavailable())
        );
        assert!(!path.exists());
        let mut initial = pass(crate::Native::create_private_ledger_file(&path));
        assert!(crate::Native::fixture_handle_not_inheritable(&initial));
        pass(initial.write_all(b"untrusted bytes"));
        assert!(crate::Native::create_private_ledger_file(&path).is_err());
        drop(initial);
        assert_eq!(pass(ledger.read_nonce_ledger_bytes()), b"untrusted bytes");
        raw_untrusted_values(&ledger);
        let limit = vec![0x5a; LIMIT];
        pass(ledger.replace_nonce_ledger_bytes(&limit));
        assert_eq!(pass(ledger.read_nonce_ledger_bytes()), limit);
        pass(fs::write(&path, vec![0x5a; LIMIT + 1]));
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        pass(fs::write(&path, &limit));
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(&vec![0x5a; LIMIT + 1]),
            Err(unavailable())
        );
        assert_eq!(pass(ledger.read_nonce_ledger_bytes()), limit);
        pass(ledger.replace_nonce_ledger_bytes(b"replacement"));
        assert_eq!(pass(ledger.read_nonce_ledger_bytes()), b"replacement");
        let held = pass(OpenOptions::new().read(true).share_mode(0).open(&path));
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        drop(held);
        assert_eq!(pass(ledger.read_nonce_ledger_bytes()), b"replacement");
        let hardlink = base.join("PiglorOS").join("hardlink");
        pass(fs::hard_link(&path, &hardlink));
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        pass(fs::remove_file(hardlink));
        retained_old_image(&guard, &ledger, base, &path);
        refuse_occupied_temporary(&ledger, base);
        refuse_replaced_directory(&ledger, base);
        drop(ledger);
        refuse_reparse_files(&guard, base, &path);
        let temporary = base.join("PiglorOS").join(TEMPORARY);
        let mut stale = pass(crate::Native::create_private_ledger_file(&temporary));
        pass(stale.write_all(b"stale"));
        drop(stale);
        let unrelated = base.join("PiglorOS").join("unrelated.tmp");
        pass(fs::write(&unrelated, b"retained"));
        let temporary_alias = base.join("PiglorOS").join("stale-alias");
        pass(fs::hard_link(&temporary, &temporary_alias));
        assert_eq!(guard.open_nonce_ledger().err(), Some(unavailable()));
        assert!(temporary.exists());
        pass(fs::remove_file(temporary_alias));
        ledger = pass(guard.open_nonce_ledger());
        assert!(!temporary.exists());
        assert_eq!(pass(fs::read(&unrelated)), b"retained");
        assert_eq!(pass(ledger.read_nonce_ledger_bytes()), b"replacement");
        for (_, failure) in STAGES {
            pass(ledger.replace_nonce_ledger_bytes(b"old"));
            assert!(ledger
                .replace_observing(b"candidate", |stage| {
                    if stage == failure {
                        Err(())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            drop(ledger);
            ledger = pass(guard.open_nonce_ledger());
            assert_eq!(
                pass(ledger.read_nonce_ledger_bytes()),
                expected_after(failure)
            );
        }
        refuse_changed_ledger(&guard, ledger, base);
        refuse_directory_swap_after_rename(&guard, base);
        refuse_staging_swap(&guard, base);
    }

    fn refuse_staging_swap(guard: &WindowsSubjectEncryptorLock, base: &Path) {
        let ledger = pass(guard.open_nonce_ledger());
        pass(ledger.replace_nonce_ledger_bytes(b"original before staging"));
        let directory = base.join("PiglorOS");
        let temporary = directory.join(TEMPORARY);
        let backup = directory.join("staging-observed-backup");
        let mut saw_stage = false;
        let result = ledger.replace_observing(b"staged candidate", |stage| {
            if stage == CommitStage::LedgerChecked {
                saw_stage = true;
                pass(fs::rename(&temporary, &backup));
                let mut substitute = pass(crate::Native::create_private_ledger_file(&temporary));
                pass(substitute.write_all(b"substitute"));
            }
            Ok(())
        });
        assert!(saw_stage, "replacement failed before staging swap");
        assert_eq!(result, Err(()));
        assert_eq!(
            pass(ledger.read_nonce_ledger_bytes()),
            b"original before staging"
        );
        assert_eq!(pass(fs::read(&backup)), b"staged candidate");
        assert_eq!(pass(fs::read(&temporary)), b"substitute");
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        drop(ledger);
        pass(fs::remove_file(&temporary));
        pass(fs::rename(&backup, &temporary));
        let recovered = pass(guard.open_nonce_ledger());
        assert_eq!(
            pass(recovered.read_nonce_ledger_bytes()),
            b"original before staging"
        );
        assert!(!temporary.exists());
    }

    fn refuse_directory_swap_after_rename(guard: &WindowsSubjectEncryptorLock, base: &Path) {
        let ledger = pass(guard.open_nonce_ledger());
        pass(ledger.replace_nonce_ledger_bytes(b"original directory"));
        let path = base.join("PiglorOS");
        let moved = base.join("moved-after-rename");
        let mut saw_stage = false;
        let result = ledger.replace_observing(b"committed candidate", |stage| {
            if stage == CommitStage::Renamed {
                saw_stage = true;
                pass(fs::rename(&path, &moved));
                pass(crate::create_private_directory(&path));
            }
            Ok(())
        });
        assert!(saw_stage, "replacement failed before directory swap");
        assert_eq!(result, Err(()));
        assert_eq!(pass(fs::read(moved.join(LEDGER))), b"committed candidate");
        assert_eq!(pass(fs::read_dir(&path)).count(), 0);
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        drop(ledger);
        pass(fs::remove_dir(&path));
        pass(fs::rename(&moved, &path));
        let recovered = pass(guard.open_nonce_ledger());
        assert_eq!(
            pass(recovered.read_nonce_ledger_bytes()),
            b"committed candidate"
        );
    }

    fn refuse_changed_ledger(
        guard: &WindowsSubjectEncryptorLock,
        ledger: WindowsNonceLedger<'_>,
        base: &Path,
    ) {
        let path = base.join("PiglorOS").join(LEDGER);
        let backup = base.join("PiglorOS").join("ledger-observed-backup");
        pass(ledger.replace_nonce_ledger_bytes(b"original"));
        let mut saw_stage = false;
        let result = ledger.replace_observing(b"candidate", |stage| {
            if stage == CommitStage::Created {
                saw_stage = true;
                pass(fs::rename(&path, &backup));
                let mut replacement = pass(crate::Native::create_private_ledger_file(&path));
                pass(replacement.write_all(b"substituted"));
            }
            Ok(())
        });
        assert!(saw_stage, "replacement failed before ledger substitution");
        assert_eq!(result, Err(()));
        assert_eq!(pass(fs::read(&path)), b"substituted");
        assert_eq!(pass(fs::read(&backup)), b"original");
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        drop(ledger);
        pass(fs::remove_file(&path));
        pass(fs::rename(&backup, &path));
        let ledger = pass(guard.open_nonce_ledger());
        assert_eq!(pass(ledger.read_nonce_ledger_bytes()), b"original");

        let mut saw_stage = false;
        let result = ledger.replace_observing(b"candidate", |stage| {
            if stage == CommitStage::Renamed {
                saw_stage = true;
                pass(fs::write(&path, b"changed after rename"));
            }
            Ok(())
        });
        assert!(saw_stage, "replacement failed before readback change");
        assert_eq!(result, Err(()));
        assert_eq!(
            pass(ledger.read_nonce_ledger_bytes()),
            b"changed after rename"
        );
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
    }

    fn recovery_requires_admitted_primary(
        guard: &WindowsSubjectEncryptorLock,
        base: &Path,
        primary: &Path,
    ) {
        let temporary = base.join("PiglorOS").join(TEMPORARY);
        let mut staged = pass(crate::Native::create_private_ledger_file(&temporary));
        pass(staged.write_all(b"staged"));
        drop(staged);
        assert_eq!(guard.open_nonce_ledger().err(), Some(unavailable()));
        assert!(!primary.exists());
        assert_eq!(pass(fs::read(&temporary)), b"staged");
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());

        let mut file = pass(crate::Native::create_private_ledger_file(primary));
        pass(file.write_all(b"primary"));
        drop(file);
        let alias = base.join("PiglorOS").join("primary-alias");
        pass(fs::hard_link(primary, &alias));
        assert_eq!(guard.open_nonce_ledger().err(), Some(unavailable()));
        assert_eq!(pass(fs::read(primary)), b"primary");
        assert_eq!(pass(fs::read(&temporary)), b"staged");
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        pass(fs::remove_file(alias));

        let held = pass(OpenOptions::new().read(true).share_mode(0).open(primary));
        assert_eq!(guard.open_nonce_ledger().err(), Some(unavailable()));
        drop(held);
        assert_eq!(pass(fs::read(primary)), b"primary");
        assert_eq!(pass(fs::read(&temporary)), b"staged");
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        pass(fs::write(primary, vec![0x5a; LIMIT + 1]));
        assert_eq!(guard.open_nonce_ledger().err(), Some(unavailable()));
        assert_eq!(pass(fs::read(primary)), vec![0x5a; LIMIT + 1]);
        assert_eq!(pass(fs::read(&temporary)), b"staged");
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        pass(fs::write(primary, b"primary"));
        let recovered = pass(guard.open_nonce_ledger());
        assert_eq!(pass(recovered.read_nonce_ledger_bytes()), b"primary");
        assert!(!temporary.exists());
        drop(recovered);
        pass(fs::remove_file(primary));
    }

    fn assert_path_admission() {
        let invalid = PathBuf::from(OsString::from_wide(&[b'x'.into(), 0, b'y'.into()]));
        assert!(crate::Native::create_private_ledger_file(&invalid).is_err());
        assert!(crate::Native::replace_ledger(&invalid, Path::new("valid")).is_err());
        assert!(crate::Native::replace_ledger(Path::new("valid"), &invalid).is_err());
        for path in [
            r"relative\path",
            r"C:relative",
            r"\\server\share\PiglorOS",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\PiglorOS",
            r"C:\base\..\PiglorOS",
        ] {
            assert!(require_dos_path(Path::new(path)).is_err(), "{path}");
        }
        for path in [r"C:\base\PiglorOS", r"\\?\C:\base\PiglorOS"] {
            assert!(require_dos_path(Path::new(path)).is_ok(), "{path}");
        }
    }

    fn retained_old_image(
        guard: &WindowsSubjectEncryptorLock,
        ledger: &WindowsNonceLedger<'_>,
        base: &Path,
        path: &Path,
    ) {
        use std::io::Read as _;

        let mut held = pass(File::open(path));
        let old_identity = pass(crate::Native::file_identity(&held));
        let before = pass(ledger.read_nonce_ledger_bytes());
        let candidate = b"candidate while old file is held";
        let result = ledger.replace_nonce_ledger_bytes(candidate);
        let mut old_bytes = Vec::new();
        pass(held.read_to_end(&mut old_bytes));
        assert_eq!(old_bytes, before);
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        if result.is_ok() {
            let new_file = pass(File::open(path));
            let new_identity = pass(crate::Native::file_identity(&new_file));
            assert_ne!(old_identity, new_identity);
            assert_eq!(pass(ledger.read_nonce_ledger_bytes()), candidate);
            drop(new_file);
            drop(held);
            pass(ledger.replace_nonce_ledger_bytes(&before));
        } else {
            assert_eq!(result, Err(unavailable()));
            assert_eq!(pass(ledger.read_nonce_ledger_bytes()), before);
            let temporary = base.join("PiglorOS").join(TEMPORARY);
            assert_eq!(pass(fs::read(&temporary)), candidate);
            drop(held);
            let recovered = pass(guard.open_nonce_ledger());
            assert!(!temporary.exists());
            assert_eq!(pass(recovered.read_nonce_ledger_bytes()), before);
            let later = b"later independent raw commit";
            pass(recovered.replace_nonce_ledger_bytes(later));
            assert_eq!(pass(recovered.read_nonce_ledger_bytes()), later);
            pass(recovered.replace_nonce_ledger_bytes(&before));
        }
    }

    fn raw_untrusted_values(ledger: &WindowsNonceLedger<'_>) {
        for bytes in [b"".as_slice(), b"not SNL1", b"\x83\x44SNL1\x02\x80"] {
            pass(ledger.replace_nonce_ledger_bytes(bytes));
            let read = pass(ledger.read_nonce_ledger_bytes());
            assert_eq!(read, bytes);
            assert!(SubjectNonceLedgerV1::from_bytes(&read).is_err());
        }
    }

    fn refuse_occupied_temporary(ledger: &WindowsNonceLedger<'_>, base: &Path) {
        let temporary = base.join("PiglorOS").join(TEMPORARY);
        let mut occupied = pass(crate::Native::create_private_ledger_file(&temporary));
        pass(occupied.write_all(b"occupied"));
        let before = pass(ledger.read_nonce_ledger_bytes());
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(b"refused"),
            Err(unavailable())
        );
        assert_eq!(pass(fs::read(&temporary)), b"occupied");
        assert_eq!(pass(ledger.read_nonce_ledger_bytes()), before);
        drop(occupied);
        pass(fs::remove_file(temporary));
    }

    fn refuse_replaced_directory(ledger: &WindowsNonceLedger<'_>, base: &Path) {
        let path = base.join("PiglorOS");
        let moved = base.join("moved-ledger-directory");
        let before = pass(ledger.read_nonce_ledger_bytes());
        pass(fs::rename(&path, &moved));
        pass(crate::create_private_directory(&path));
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(b"refused"),
            Err(unavailable())
        );
        pass(fs::remove_dir(&path));
        pass(fs::rename(moved, &path));
        assert_eq!(pass(ledger.read_nonce_ledger_bytes()), before);
    }

    fn refuse_reparse_files(guard: &WindowsSubjectEncryptorLock, base: &Path, path: &Path) {
        let backup = base.join("PiglorOS").join("ledger-fixture-backup");
        pass(fs::rename(path, &backup));
        pass(symlink_file(&backup, path));
        let ledger = pass(guard.open_nonce_ledger());
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(b"refused"),
            Err(unavailable())
        );
        drop(ledger);
        assert!(pass(fs::symlink_metadata(path)).file_type().is_symlink());
        pass(fs::remove_file(path));
        pass(fs::rename(&backup, path));
        let temporary = base.join("PiglorOS").join(TEMPORARY);
        pass(symlink_file(path, &temporary));
        assert!(guard.open_nonce_ledger().is_err());
        assert!(pass(fs::symlink_metadata(&temporary))
            .file_type()
            .is_symlink());
        pass(fs::remove_file(temporary));
    }

    fn expected_after(stage: CommitStage) -> &'static [u8] {
        if matches!(stage, CommitStage::Renamed | CommitStage::ReadBack) {
            b"candidate"
        } else {
            b"old"
        }
    }

    fn crash_stages(base: &Path) {
        for (name, stage) in STAGES {
            for control in [false, true] {
                let guard = pass(WindowsSubjectEncryptorLock::acquire(base));
                let ledger = pass(guard.open_nonce_ledger());
                pass(ledger.replace_nonce_ledger_bytes(b"old"));
                drop(ledger);
                drop(guard);
                let marker = base.join(format!("probe-{name}"));
                let mut command = Command::new(pass(std::env::current_exe()));
                if control {
                    command.env(CONTROL, "1");
                }
                let mut probe = Probe(pass(
                    command
                        .args([
                            "--exact",
                            "tests::windows_nonce_ledger_storage_native",
                            "--nocapture",
                            "--test-threads=1",
                        ])
                        .env(PROBE, name)
                        .env(BASE, base)
                        .env(MARKER, &marker)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(if control {
                            Stdio::inherit()
                        } else {
                            Stdio::null()
                        })
                        .spawn(),
                ));
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    let read = fs::read(&marker);
                    assert!(
                        matches!(
                            read.as_ref().err().map(io::Error::kind),
                            None | Some(io::ErrorKind::NotFound)
                        ),
                        "storage probe marker could not be read"
                    );
                    let observed = read.unwrap_or_default();
                    assert!(
                        name.as_bytes().starts_with(&observed),
                        "storage probe marker mismatch"
                    );
                    if observed == name.as_bytes() {
                        break;
                    }
                    assert!(
                        pass(probe.0.try_wait()).is_none(),
                        "storage probe exited before its checkpoint"
                    );
                    assert!(
                        Instant::now() < deadline,
                        "storage probe exceeded its deadline"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                if control {
                    drop(probe.0.stdin.take());
                } else {
                    pass(probe.0.kill());
                }
                let status = loop {
                    if let Some(status) = pass(probe.0.try_wait()) {
                        break status;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "storage probe exceeded its deadline"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                };
                assert_eq!(
                    status.success(),
                    control,
                    "only the storage control probe exits successfully"
                );
                drop(probe);
                pass(fs::remove_file(marker));
                let guard = pass(WindowsSubjectEncryptorLock::acquire(base));
                let ledger = pass(guard.open_nonce_ledger());
                assert_eq!(
                    pass(ledger.read_nonce_ledger_bytes()),
                    expected_after(stage)
                );
            }
        }
    }

    fn checked_fixture(base: &Path) {
        let guard = pass(WindowsSubjectEncryptorLock::acquire(base));
        let mut ledger = pass(guard.open_nonce_ledger());
        let path = base.join("PiglorOS").join(LEDGER);
        let store_path = base.join("PiglorOS").join("fixture-store.db");
        let mut fixture_store = pass(crate::Native::create_private_ledger_file(&store_path));
        pass(fixture_store.write_all(b"fixture store"));
        drop(fixture_store);
        let store_file = pass(File::open(&store_path));
        let store_id = pass(super::super::store_file_identity::store_file_id(
            &store_file,
        ));
        let expected_row = SubjectNonceLedgerRowV1 {
            owner_id: "subject:000102030405060708090a0b0c0d0e0f".to_owned(),
            epoch: 1,
            root_material_digest: [0x33; 32],
            store_file_id: SubjectStoreFileIdV1::Windows {
                volume_serial: pass(u32::try_from(store_id[0])),
                file_index: store_id[1],
            },
            data_next: 1,
            bootstrap_next: 1,
        };
        let initial = pass(SubjectNonceLedgerV1::new([expected_row.clone()]));
        pass(ledger.replace_nonce_ledger_bytes(initial.as_bytes()));
        let parsed = pass(SubjectNonceLedgerV1::from_bytes(&pass(
            ledger.read_nonce_ledger_bytes(),
        )));
        assert_eq!(parsed.rows().next(), Some(&expected_row));
        let wrong_root = SubjectNonceLedgerRowV1 {
            root_material_digest: [0x44; 32],
            ..expected_row.clone()
        };
        assert_eq!(
            parsed.advance_counter(&wrong_root, SubjectKeyUseV1::Data),
            Err(SubjectNonceLedgerErrorV1::RowMismatch)
        );
        let candidate = pass(parsed.advance_counter(&expected_row, SubjectKeyUseV1::Data));
        assert!(ledger
            .replace_observing(candidate.as_bytes(), |stage| {
                if stage == CommitStage::Renamed {
                    Err(())
                } else {
                    Ok(())
                }
            })
            .is_err());
        drop(ledger);
        ledger = pass(guard.open_nonce_ledger());
        let recovered = pass(SubjectNonceLedgerV1::from_bytes(&pass(
            ledger.read_nonce_ledger_bytes(),
        )));
        assert_eq!(recovered, candidate);
        let successor_row = pass(recovered.rows().next().ok_or("missing fixture row")).clone();
        assert_eq!(successor_row.data_next, 2);
        let successor = pass(recovered.advance_counter(&successor_row, SubjectKeyUseV1::Data));
        pass(ledger.replace_nonce_ledger_bytes(successor.as_bytes()));
        let committed = pass(SubjectNonceLedgerV1::from_bytes(&pass(
            ledger.read_nonce_ledger_bytes(),
        )));
        assert_eq!(
            pass(committed.rows().next().ok_or("missing committed row")).data_next,
            3
        );
        drop(store_file);
        let output = pass(
            Command::new("icacls.exe")
                .arg(&path)
                .args(["/grant", "*S-1-1-0:(R)"])
                .output(),
        );
        assert!(output.status.success());
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(b"refused"),
            Err(unavailable())
        );
    }
}
