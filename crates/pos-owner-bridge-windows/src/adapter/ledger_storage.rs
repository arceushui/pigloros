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
        Self::same_name(&previous, &self.path.join(LEDGER))?;
        Self::same_name(&temporary, &temporary_path)?;
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
                let file = self.open_existing(TEMPORARY)?;
                Self::same_name(&file, &path)?;
                drop(file);
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
    const BASE: &str = "PIGLOROS_WINDOWS_NONCE_STORAGE_BASE";
    const MARKER: &str = "PIGLOROS_WINDOWS_NONCE_STORAGE_MARKER";
    const STAGES: [(&str, CommitStage); 5] = [
        ("created", CommitStage::Created),
        ("written", CommitStage::Written),
        ("synced", CommitStage::FileSynced),
        ("renamed", CommitStage::Renamed),
        ("readback", CommitStage::ReadBack),
    ];

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
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
        let fixture = Fixture(base);
        raw_boundaries(&fixture.0)?;
        crash_stages(&fixture.0)?;
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
        let _result = ledger.replace_observing(b"candidate", |stage| {
            if stage == selected {
                fs::write(&marker, b"ready").map_err(|_| ())?;
                let mut line = String::new();
                io::stdin().read_line(&mut line).map_err(|_| ())?;
                return Err(());
            }
            Ok(())
        });
        Err("storage probe returned without interruption".into())
    }

    fn raw_boundaries(base: &Path) -> TestResult {
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
        let guard = WindowsSubjectEncryptorLock::acquire(base).map_err(|_| "raw fixture lock")?;
        let mut ledger = guard
            .open_nonce_ledger()
            .map_err(|_| "open initial raw directory")?;
        let path = base.join("PiglorOS").join(LEDGER);
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
        drop(ledger);
        refuse_reparse_files(&guard, base, &path)?;
        let temporary = base.join("PiglorOS").join(TEMPORARY);
        let mut stale = crate::Native::create_private_ledger_file(&temporary)
            .map_err(|()| "create stale test file")?;
        stale.write_all(b"stale")?;
        drop(stale);
        let temporary_alias = base.join("PiglorOS").join("stale-alias");
        fs::hard_link(&temporary, &temporary_alias)?;
        assert!(guard.open_nonce_ledger().is_err());
        assert!(temporary.exists());
        fs::remove_file(temporary_alias)?;
        ledger = guard.open_nonce_ledger()?;
        assert!(!temporary.exists());
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

    fn crash_stages(base: &Path) -> TestResult {
        for (name, stage) in STAGES {
            let guard = WindowsSubjectEncryptorLock::acquire(base)?;
            let ledger = guard.open_nonce_ledger()?;
            ledger.replace_nonce_ledger_bytes(b"old")?;
            drop(ledger);
            drop(guard);
            let marker = base.join(format!("probe-{name}"));
            let mut child = Command::new(std::env::current_exe()?)
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
                .stderr(Stdio::null())
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(30);
            while !marker.exists() {
                if child.try_wait()?.is_some() {
                    return Err("storage probe exited before its checkpoint".into());
                }
                if Instant::now() >= deadline {
                    child.kill()?;
                    child.wait()?;
                    return Err("storage probe exceeded its deadline".into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            child.kill()?;
            child.wait()?;
            fs::remove_file(marker)?;
            let guard = WindowsSubjectEncryptorLock::acquire(base)?;
            let ledger = guard.open_nonce_ledger()?;
            assert_eq!(ledger.read_nonce_ledger_bytes()?, expected_after(stage));
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
