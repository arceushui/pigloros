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
        require_dos_path(&path)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => crate::verify_private_directory(&path).map_err(|_| ())?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                crate::create_private_directory(&path).map_err(|_| ())?;
            }
            Err(_) => return Err(()),
        }
        crate::Native::cleanup_path_ntfs(&path)?;
        let directory = open_directory(&path)?;
        let volume = crate::Native::cleanup_file_volume(&directory)?;
        let store = Self {
            _guard: guard,
            directory,
            path,
            volume,
        };
        store.admit_directory()?;
        store.remove_stale_temporary()?;
        Ok(store)
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
        self.admit_directory()?;
        let file = self.open_existing(LEDGER)?;
        read_bounded(file)
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
        self.admit_directory()?;
        let previous = self.open_existing(LEDGER)?;
        let temporary_path = self.path.join(TEMPORARY);
        let mut temporary = crate::Native::create_private_ledger_file(&temporary_path)?;
        self.validate_file(&temporary, &temporary_path)?;
        after(CommitStage::Created)?;
        temporary.write_all(bytes).map_err(|_| ())?;
        after(CommitStage::Written)?;
        temporary.sync_all().map_err(|_| ())?;
        after(CommitStage::FileSynced)?;
        self.admit_directory()?;
        after(CommitStage::DirectoryChecked)?;
        Self::same_name(&previous, &self.path.join(LEDGER))?;
        after(CommitStage::LedgerChecked)?;
        Self::same_name(&temporary, &temporary_path)?;
        after(CommitStage::TemporaryChecked)?;
        drop(previous);
        drop(temporary);
        crate::Native::replace_ledger(&temporary_path, &self.path.join(LEDGER))?;
        after(CommitStage::Renamed)?;
        self.admit_directory()?;
        let observed = self.open_existing(LEDGER)?;
        if read_bounded(observed)? != bytes {
            return Err(());
        }
        after(CommitStage::ReadBack)?;
        Ok(())
    }

    fn admit_directory(&self) -> Result<(), ()> {
        crate::verify_private_directory(&self.path).map_err(|_| ())?;
        if crate::Native::cleanup_file_volume(&self.directory)? != self.volume {
            return Err(());
        }
        let reopened = open_directory(&self.path)?;
        if crate::Native::file_identity(&self.directory)?
            != crate::Native::file_identity(&reopened)?
        {
            return Err(());
        }
        Ok(())
    }

    fn validate_file(&self, file: &File, path: &Path) -> Result<(), ()> {
        let metadata = file.metadata().map_err(|_| ())?;
        if !metadata.is_file() || metadata.file_attributes() & REPARSE_POINT != 0 {
            return Err(());
        }
        crate::Native::require_private_file(file)?;
        if crate::Native::file_link_count(file)? != 1
            || crate::Native::cleanup_file_volume(file)? != self.volume
        {
            return Err(());
        }
        Self::same_name(file, path)
    }

    fn same_name(file: &File, path: &Path) -> Result<(), ()> {
        let reopened = open_file(path)?;
        if crate::Native::file_identity(file)? != crate::Native::file_identity(&reopened)? {
            return Err(());
        }
        Ok(())
    }

    fn open_existing(&self, name: &str) -> Result<File, ()> {
        let path = self.path.join(name);
        let file = open_file(&path)?;
        self.validate_file(&file, &path)?;
        Ok(file)
    }

    fn remove_stale_temporary(&self) -> Result<(), ()> {
        let path = self.path.join(TEMPORARY);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(()),
            Ok(_) => {
                let primary = self.open_existing(LEDGER)?;
                let temporary = self.open_existing(TEMPORARY)?;
                read_bounded(primary.try_clone().map_err(|_| ())?)?;
                read_bounded(temporary.try_clone().map_err(|_| ())?)?;
                self.admit_directory()?;
                Self::same_name(&primary, &self.path.join(LEDGER))?;
                Self::same_name(&temporary, &path)?;
                drop(primary);
                drop(temporary);
                fs::remove_file(path).map_err(|_| ())
            }
        }
    }
}

fn open_directory(path: &Path) -> Result<File, ()> {
    OpenOptions::new()
        .read(true)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|_| ())
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
        .map_err(|_| ())
}

fn read_bounded(file: File) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    file.take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > LIMIT {
        return Err(());
    }
    Ok(bytes)
}

const fn unavailable() -> BridgeError {
    BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable)
}

#[cfg(test)]
impl crate::Native {
    pub(crate) fn exercise_ledger_storage() -> Result<(), Box<dyn std::error::Error>> {
        native_tests::exercise()
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

    type TestResult = Result<(), Box<dyn std::error::Error>>;
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

    struct Fixture(PathBuf, bool);
    impl Drop for Fixture {
        fn drop(&mut self) {
            if !self.1 {
                let _removed = fs::remove_dir_all(&self.0);
            }
        }
    }

    pub(super) fn exercise() -> TestResult {
        let _serial = super::super::nonce_ledger::NONCE_TEST_LOCK
            .lock()
            .map_err(|_| "nonce test lock poisoned")?;
        if let Ok(requested) = std::env::var(PROBE) {
            return run_probe(&requested);
        }
        let base = std::env::temp_dir().join(format!(
            "piglor-nonce-ledger-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&base)?;
        let mut fixture = Fixture(base, false);
        raw_boundaries(&fixture.0)?;
        crash_stages(&mut fixture)?;
        checked_fixture(&fixture.0)
    }

    fn run_probe(requested: &str) -> TestResult {
        let base = PathBuf::from(std::env::var_os(BASE).ok_or("missing probe base")?);
        let marker = PathBuf::from(std::env::var_os(MARKER).ok_or("missing probe marker")?);
        let selected = STAGES
            .iter()
            .find_map(|(name, stage)| (*name == requested).then_some(*stage))
            .ok_or("unknown probe stage")?;
        let guard = WindowsSubjectEncryptorLock::acquire(&base)?;
        let ledger = guard.open_nonce_ledger()?;
        let control = std::env::var_os(CONTROL).is_some();
        let mut saw_eof = false;
        if control {
            writeln!(
                io::stderr(),
                "storage control profile: {:?}",
                std::env::var_os("LLVM_PROFILE_FILE")
            )?;
        }
        let result = ledger.replace_observing(b"candidate", |stage| {
            if stage == selected {
                fs::write(&marker, requested.as_bytes()).map_err(|_| ())?;
                let mut line = String::new();
                let bytes = io::stdin().read_line(&mut line).map_err(|_| ())?;
                saw_eof = bytes == 0;
                return Err(());
            }
            Ok(())
        });
        if control && saw_eof && result == Err(()) {
            Ok(())
        } else {
            Err("storage probe returned without interruption".into())
        }
    }

    fn raw_boundaries(base: &Path) -> TestResult {
        assert_path_admission();
        let guard = WindowsSubjectEncryptorLock::acquire(base).map_err(|_| "raw fixture lock")?;
        let mut ledger = guard
            .open_nonce_ledger()
            .map_err(|_| "open initial raw directory")?;
        let path = base.join("PiglorOS").join(LEDGER);
        recovery_requires_admitted_primary(&guard, base, &path)?;
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(b"missing"),
            Err(unavailable())
        );
        assert!(!path.exists());
        let mut initial = crate::Native::create_private_ledger_file(&path)
            .map_err(|()| "create initial test file")?;
        assert!(crate::Native::fixture_handle_not_inheritable(&initial));
        initial.write_all(b"untrusted bytes")?;
        assert!(crate::Native::create_private_ledger_file(&path).is_err());
        drop(initial);
        assert_eq!(
            ledger
                .read_nonce_ledger_bytes()
                .map_err(|_| "read initial raw file")?,
            b"untrusted bytes"
        );
        raw_untrusted_values(&ledger)?;
        let limit = vec![0x5a; LIMIT];
        ledger
            .replace_nonce_ledger_bytes(&limit)
            .map_err(|_| "replace raw file at byte limit")?;
        assert_eq!(
            ledger
                .read_nonce_ledger_bytes()
                .map_err(|_| "read raw file at byte limit")?,
            limit
        );
        fs::write(&path, vec![0x5a; LIMIT + 1])?;
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        fs::write(&path, &limit)?;
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(&vec![0x5a; LIMIT + 1]),
            Err(unavailable())
        );
        assert_eq!(ledger.read_nonce_ledger_bytes()?, limit);
        ledger.replace_nonce_ledger_bytes(b"replacement")?;
        assert_eq!(ledger.read_nonce_ledger_bytes()?, b"replacement");
        let held = OpenOptions::new().read(true).share_mode(0).open(&path)?;
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        drop(held);
        assert_eq!(ledger.read_nonce_ledger_bytes()?, b"replacement");
        let hardlink = base.join("PiglorOS").join("hardlink");
        fs::hard_link(&path, &hardlink)?;
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        fs::remove_file(hardlink)?;
        retained_old_image(&guard, &ledger, base, &path)?;
        refuse_occupied_temporary(&ledger, base)?;
        refuse_replaced_directory(&ledger, base)?;
        drop(ledger);
        refuse_reparse_files(&guard, base, &path)?;
        let temporary = base.join("PiglorOS").join(TEMPORARY);
        let mut stale = crate::Native::create_private_ledger_file(&temporary)
            .map_err(|()| "create stale test file")?;
        stale.write_all(b"stale")?;
        drop(stale);
        let unrelated = base.join("PiglorOS").join("unrelated.tmp");
        fs::write(&unrelated, b"retained")?;
        let temporary_alias = base.join("PiglorOS").join("stale-alias");
        fs::hard_link(&temporary, &temporary_alias)?;
        assert_eq!(guard.open_nonce_ledger().err(), Some(unavailable()));
        assert!(temporary.exists());
        fs::remove_file(temporary_alias)?;
        ledger = guard.open_nonce_ledger()?;
        assert!(!temporary.exists());
        assert_eq!(fs::read(&unrelated)?, b"retained");
        assert_eq!(ledger.read_nonce_ledger_bytes()?, b"replacement");
        for (_, failure) in STAGES {
            ledger.replace_nonce_ledger_bytes(b"old")?;
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
            ledger = guard.open_nonce_ledger()?;
            assert_eq!(ledger.read_nonce_ledger_bytes()?, expected_after(failure));
        }
        Ok(())
    }

    fn recovery_requires_admitted_primary(
        guard: &WindowsSubjectEncryptorLock,
        base: &Path,
        primary: &Path,
    ) -> TestResult {
        let temporary = base.join("PiglorOS").join(TEMPORARY);
        let mut staged = crate::Native::create_private_ledger_file(&temporary)
            .map_err(|()| "create recovery staging fixture")?;
        staged.write_all(b"staged")?;
        drop(staged);
        assert_eq!(guard.open_nonce_ledger().err(), Some(unavailable()));
        assert!(!primary.exists());
        assert_eq!(fs::read(&temporary)?, b"staged");
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());

        let mut file = crate::Native::create_private_ledger_file(primary)
            .map_err(|()| "create recovery primary fixture")?;
        file.write_all(b"primary")?;
        drop(file);
        let alias = base.join("PiglorOS").join("primary-alias");
        fs::hard_link(primary, &alias)?;
        assert_eq!(guard.open_nonce_ledger().err(), Some(unavailable()));
        assert_eq!(fs::read(primary)?, b"primary");
        assert_eq!(fs::read(&temporary)?, b"staged");
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        fs::remove_file(alias)?;

        let held = OpenOptions::new().read(true).share_mode(0).open(primary)?;
        assert_eq!(guard.open_nonce_ledger().err(), Some(unavailable()));
        drop(held);
        assert_eq!(fs::read(primary)?, b"primary");
        assert_eq!(fs::read(&temporary)?, b"staged");
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        fs::write(primary, vec![0x5a; LIMIT + 1])?;
        assert_eq!(guard.open_nonce_ledger().err(), Some(unavailable()));
        assert_eq!(fs::read(primary)?, vec![0x5a; LIMIT + 1]);
        assert_eq!(fs::read(&temporary)?, b"staged");
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        fs::write(primary, b"primary")?;
        let recovered = guard.open_nonce_ledger()?;
        assert_eq!(recovered.read_nonce_ledger_bytes()?, b"primary");
        assert!(!temporary.exists());
        drop(recovered);
        fs::remove_file(primary)?;
        Ok(())
    }

    fn assert_path_admission() {
        let invalid = PathBuf::from(OsString::from_wide(&[b'x'.into(), 0, b'y'.into()]));
        assert!(crate::Native::create_private_ledger_file(&invalid).is_err());
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
    ) -> TestResult {
        use std::io::Read as _;

        let mut held = File::open(path)?;
        let old_identity = crate::Native::file_identity(&held).map_err(|()| "old file identity")?;
        let before = ledger.read_nonce_ledger_bytes()?;
        let candidate = b"candidate while old file is held";
        let result = ledger.replace_nonce_ledger_bytes(candidate);
        let mut old_bytes = Vec::new();
        held.read_to_end(&mut old_bytes)?;
        assert_eq!(old_bytes, before);
        assert!(WindowsSubjectEncryptorLock::acquire(base).is_err());
        if result.is_ok() {
            let new_file = File::open(path)?;
            let new_identity =
                crate::Native::file_identity(&new_file).map_err(|()| "new file identity")?;
            assert_ne!(old_identity, new_identity);
            assert_eq!(ledger.read_nonce_ledger_bytes()?, candidate);
            drop(new_file);
            drop(held);
            ledger.replace_nonce_ledger_bytes(&before)?;
        } else {
            assert_eq!(result, Err(unavailable()));
            assert_eq!(ledger.read_nonce_ledger_bytes()?, before);
            let temporary = base.join("PiglorOS").join(TEMPORARY);
            assert_eq!(fs::read(&temporary)?, candidate);
            drop(held);
            let recovered = guard.open_nonce_ledger()?;
            assert!(!temporary.exists());
            assert_eq!(recovered.read_nonce_ledger_bytes()?, before);
            let later = b"later independent raw commit";
            recovered.replace_nonce_ledger_bytes(later)?;
            assert_eq!(recovered.read_nonce_ledger_bytes()?, later);
            recovered.replace_nonce_ledger_bytes(&before)?;
        }
        Ok(())
    }

    fn raw_untrusted_values(ledger: &WindowsNonceLedger<'_>) -> TestResult {
        for bytes in [b"".as_slice(), b"not SNL1", b"\x83\x44SNL1\x02\x80"] {
            ledger.replace_nonce_ledger_bytes(bytes)?;
            let read = ledger.read_nonce_ledger_bytes()?;
            assert_eq!(read, bytes);
            assert!(SubjectNonceLedgerV1::from_bytes(&read).is_err());
        }
        Ok(())
    }

    fn refuse_occupied_temporary(ledger: &WindowsNonceLedger<'_>, base: &Path) -> TestResult {
        let temporary = base.join("PiglorOS").join(TEMPORARY);
        let mut occupied = crate::Native::create_private_ledger_file(&temporary)
            .map_err(|()| "create occupied staging fixture")?;
        occupied.write_all(b"occupied")?;
        let before = ledger.read_nonce_ledger_bytes()?;
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(b"refused"),
            Err(unavailable())
        );
        assert_eq!(fs::read(&temporary)?, b"occupied");
        assert_eq!(ledger.read_nonce_ledger_bytes()?, before);
        drop(occupied);
        fs::remove_file(temporary)?;
        Ok(())
    }

    fn refuse_replaced_directory(ledger: &WindowsNonceLedger<'_>, base: &Path) -> TestResult {
        let path = base.join("PiglorOS");
        let moved = base.join("moved-ledger-directory");
        let before = ledger.read_nonce_ledger_bytes()?;
        fs::rename(&path, &moved)?;
        crate::create_private_directory(&path).map_err(|_| "create replacement directory")?;
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(b"refused"),
            Err(unavailable())
        );
        fs::remove_dir(&path)?;
        fs::rename(moved, &path)?;
        assert_eq!(ledger.read_nonce_ledger_bytes()?, before);
        Ok(())
    }

    fn refuse_reparse_files(
        guard: &WindowsSubjectEncryptorLock,
        base: &Path,
        path: &Path,
    ) -> TestResult {
        let backup = base.join("PiglorOS").join("ledger-fixture-backup");
        fs::rename(path, &backup)?;
        symlink_file(&backup, path)?;
        let ledger = guard.open_nonce_ledger()?;
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(b"refused"),
            Err(unavailable())
        );
        drop(ledger);
        assert!(fs::symlink_metadata(path)?.file_type().is_symlink());
        fs::remove_file(path)?;
        fs::rename(&backup, path)?;
        let temporary = base.join("PiglorOS").join(TEMPORARY);
        symlink_file(path, &temporary)?;
        assert!(guard.open_nonce_ledger().is_err());
        assert!(fs::symlink_metadata(&temporary)?.file_type().is_symlink());
        fs::remove_file(temporary)?;
        Ok(())
    }

    fn expected_after(stage: CommitStage) -> &'static [u8] {
        if matches!(stage, CommitStage::Renamed | CommitStage::ReadBack) {
            b"candidate"
        } else {
            b"old"
        }
    }

    fn crash_stages(fixture: &mut Fixture) -> TestResult {
        let base = fixture.0.clone();
        for (name, stage) in STAGES {
            for control in [false, true] {
                let guard = WindowsSubjectEncryptorLock::acquire(&base)?;
                let ledger = guard.open_nonce_ledger()?;
                ledger.replace_nonce_ledger_bytes(b"old")?;
                drop(ledger);
                drop(guard);
                let marker = base.join(format!("probe-{name}"));
                let mut command = Command::new(std::env::current_exe()?);
                if control {
                    command.env(CONTROL, "1");
                }
                let mut child = command
                    .args([
                        "--exact",
                        "tests::windows_nonce_ledger_storage_native",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(PROBE, name)
                    .env(BASE, &base)
                    .env(MARKER, &marker)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(if control {
                        Stdio::inherit()
                    } else {
                        Stdio::null()
                    })
                    .spawn()?;
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut retired = false;
                let result = (|| -> TestResult {
                    loop {
                        match fs::read(&marker) {
                            Ok(bytes) if bytes == name.as_bytes() => break,
                            Ok(bytes) if name.as_bytes().starts_with(&bytes) => {}
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                            Ok(_) => return Err("storage probe marker mismatch".into()),
                            Err(error) => return Err(error.into()),
                        }
                        if child.try_wait()?.is_some() {
                            retired = true;
                            return Err("storage probe exited before its checkpoint".into());
                        }
                        if Instant::now() >= deadline {
                            return Err("storage probe exceeded its deadline".into());
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    if control {
                        drop(child.stdin.take());
                    } else {
                        child.kill()?;
                    }
                    loop {
                        if let Some(status) = child.try_wait()? {
                            retired = true;
                            if control && !status.success() {
                                return Err("storage control did not exit successfully".into());
                            }
                            if !control && status.success() {
                                return Err("storage crash probe unexpectedly succeeded".into());
                            }
                            break;
                        }
                        if Instant::now() >= deadline {
                            return Err("storage probe exceeded its deadline".into());
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Ok(())
                })();
                if !retired {
                    let killed = child.kill();
                    drop(child.stdin.take());
                    let waited = if killed.is_ok() {
                        child.wait().map(|_| true)
                    } else {
                        child.try_wait().map(|status| status.is_some())
                    };
                    if !matches!(&waited, Ok(true)) {
                        fixture.1 = true;
                        let _diagnostic = writeln!(
                            io::stderr(),
                            "storage probe could not be retired: kill={killed:?}, wait={waited:?}"
                        );
                    }
                }
                result?;
                fs::remove_file(marker)?;
                let guard = WindowsSubjectEncryptorLock::acquire(&base)?;
                let ledger = guard.open_nonce_ledger()?;
                assert_eq!(ledger.read_nonce_ledger_bytes()?, expected_after(stage));
            }
        }
        Ok(())
    }

    fn checked_fixture(base: &Path) -> TestResult {
        let guard = WindowsSubjectEncryptorLock::acquire(base)?;
        let mut ledger = guard.open_nonce_ledger()?;
        let path = base.join("PiglorOS").join(LEDGER);
        let store_path = base.join("PiglorOS").join("fixture-store.db");
        let mut fixture_store = crate::Native::create_private_ledger_file(&store_path)
            .map_err(|()| "create fixture store")?;
        fixture_store.write_all(b"fixture store")?;
        drop(fixture_store);
        let store_file = File::open(&store_path)?;
        let store_id = super::super::store_file_identity::store_file_id(&store_file)?;
        let expected_row = SubjectNonceLedgerRowV1 {
            owner_id: "subject:000102030405060708090a0b0c0d0e0f".to_owned(),
            epoch: 1,
            root_material_digest: [0x33; 32],
            store_file_id: SubjectStoreFileIdV1::Windows {
                volume_serial: u32::try_from(store_id[0])?,
                file_index: store_id[1],
            },
            data_next: 1,
            bootstrap_next: 1,
        };
        let initial = SubjectNonceLedgerV1::new([expected_row.clone()])?;
        ledger.replace_nonce_ledger_bytes(initial.as_bytes())?;
        let parsed = SubjectNonceLedgerV1::from_bytes(&ledger.read_nonce_ledger_bytes()?)?;
        assert_eq!(parsed.rows().next(), Some(&expected_row));
        let wrong_root = SubjectNonceLedgerRowV1 {
            root_material_digest: [0x44; 32],
            ..expected_row.clone()
        };
        assert_eq!(
            parsed.advance_counter(&wrong_root, SubjectKeyUseV1::Data),
            Err(SubjectNonceLedgerErrorV1::RowMismatch)
        );
        let candidate = parsed.advance_counter(&expected_row, SubjectKeyUseV1::Data)?;
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
        ledger = guard.open_nonce_ledger()?;
        let recovered = SubjectNonceLedgerV1::from_bytes(&ledger.read_nonce_ledger_bytes()?)?;
        assert_eq!(recovered, candidate);
        let successor_row = recovered
            .rows()
            .next()
            .ok_or("missing fixture row")?
            .clone();
        assert_eq!(successor_row.data_next, 2);
        let successor = recovered.advance_counter(&successor_row, SubjectKeyUseV1::Data)?;
        ledger.replace_nonce_ledger_bytes(successor.as_bytes())?;
        let committed = SubjectNonceLedgerV1::from_bytes(&ledger.read_nonce_ledger_bytes()?)?;
        assert_eq!(
            committed
                .rows()
                .next()
                .ok_or("missing committed row")?
                .data_next,
            3
        );
        drop(store_file);
        let output = Command::new("icacls.exe")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:(R)"])
            .output()?;
        assert!(output.status.success());
        assert_eq!(ledger.read_nonce_ledger_bytes(), Err(unavailable()));
        assert_eq!(
            ledger.replace_nonce_ledger_bytes(b"refused"),
            Err(unavailable())
        );
        Ok(())
    }
}
