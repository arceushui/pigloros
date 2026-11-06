#![cfg(windows)]
#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pos_owner_bridge::channel::channel;
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::host::FakeProbe;
use pos_owner_bridge::{
    cleanup_record_bytes, folder_name, BridgeConfig, BridgeError, CleanupStore, OwnerBridge,
    ProcessIdentity, QuarantineCode, RestartProgress,
};
use pos_owner_bridge_codec::{CeremonyId, ImagePathSha256};

use super::files::Files;
use super::io::{FileIo, OsIo};
use super::WindowsCleanupStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ID: CeremonyId = CeremonyId::from_bytes([9; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Created,
    Partial,
    Written,
    Flushed,
    Published,
    Readback,
}

impl Stage {
    const ALL: [Self; 6] = [
        Self::Created,
        Self::Partial,
        Self::Written,
        Self::Flushed,
        Self::Published,
        Self::Readback,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Partial => "partial",
            Self::Written => "written",
            Self::Flushed => "flushed",
            Self::Published => "published",
            Self::Readback => "readback",
        }
    }
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    Qualify,
    Open(usize),
    VolumeError(usize),
    VolumeChanged(usize),
    Write,
    Partial,
    Flush,
    PublishSourceOnly,
    PublishFinalOnly,
    PublishBoth,
    Read,
    ChangedReadback,
    Pause(Stage),
}

struct Effects {
    fault: Fault,
    root: PathBuf,
    opens: AtomicUsize,
    volumes: AtomicUsize,
    reads: AtomicUsize,
}

impl Effects {
    fn new(root: &Path, fault: Fault) -> Self {
        Self {
            fault,
            root: root.to_path_buf(),
            opens: AtomicUsize::new(0),
            volumes: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
        }
    }

    fn checkpoint(&self, stage: Stage) -> io::Result<()> {
        if matches!(self.fault, Fault::Pause(selected) if selected == stage) {
            fs::write(self.root.join("checkpoint"), stage.name())?;
            loop {
                std::thread::park();
            }
        }
        Ok(())
    }
}

fn failure() -> io::Error {
    io::Error::other("injected cleanup storage failure")
}

impl FileIo for Effects {
    fn qualify_path(&self, path: &Path) -> io::Result<()> {
        if matches!(self.fault, Fault::Qualify) {
            return Err(failure());
        }
        OsIo.qualify_path(path)
    }

    fn volume(&self, file: &File) -> io::Result<u32> {
        let call = self.volumes.fetch_add(1, Ordering::Relaxed) + 1;
        if matches!(self.fault, Fault::VolumeError(selected) if selected == call) {
            return Err(failure());
        }
        let serial = OsIo.volume(file)?;
        Ok(
            if matches!(self.fault, Fault::VolumeChanged(selected) if selected == call) {
                serial ^ 1
            } else {
                serial
            },
        )
    }

    fn open(&self, path: &Path, options: &OpenOptions) -> io::Result<File> {
        let call = self.opens.fetch_add(1, Ordering::Relaxed) + 1;
        if matches!(self.fault, Fault::Open(selected) if selected == call) {
            return Err(failure());
        }
        let file = OsIo.open(path, options)?;
        if path
            .extension()
            .is_some_and(|extension| extension == "pending")
        {
            self.checkpoint(Stage::Created)?;
        }
        Ok(file)
    }

    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        if matches!(self.fault, Fault::Write) {
            return Err(failure());
        }
        if matches!(self.fault, Fault::Partial | Fault::Pause(Stage::Partial)) {
            file.write_all(&bytes[..bytes.len() / 2])?;
            self.checkpoint(Stage::Partial)?;
            return Err(failure());
        }
        OsIo.write(file, bytes)?;
        self.checkpoint(Stage::Written)
    }

    fn flush(&self, file: &File) -> io::Result<()> {
        if matches!(self.fault, Fault::Flush) {
            return Err(failure());
        }
        OsIo.flush(file)?;
        self.checkpoint(Stage::Flushed)
    }

    fn publish(&self, pending: &Path, committed: &Path) -> io::Result<()> {
        match self.fault {
            Fault::PublishSourceOnly => return Err(failure()),
            Fault::PublishBoth => {
                fs::copy(pending, committed)?;
                return Err(failure());
            }
            _ => {}
        }
        OsIo.publish(pending, committed)?;
        if matches!(self.fault, Fault::PublishFinalOnly) {
            return Err(failure());
        }
        self.checkpoint(Stage::Published)
    }

    fn read(&self, file: &mut File) -> io::Result<Vec<u8>> {
        let call = self.reads.fetch_add(1, Ordering::Relaxed) + 1;
        if matches!(self.fault, Fault::Read) && call == 1 {
            return Err(failure());
        }
        let mut bytes = OsIo.read(file)?;
        if matches!(self.fault, Fault::ChangedReadback) && call == 1 {
            bytes.push(0);
        }
        self.checkpoint(Stage::Readback)?;
        Ok(bytes)
    }
}

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cleanup-fault-{}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        crate::create_private_directory(&path)?;
        Ok(Self(path))
    }
    fn open(&self, fault: Fault) -> Result<WindowsCleanupStore, pos_owner_bridge::CleanupError> {
        Files::open_with(self.0.clone(), Box::new(Effects::new(&self.0, fault)))
            .map(WindowsCleanupStore::new)
    }
    fn record_path(&self, extension: &str) -> PathBuf {
        self.0
            .join("records")
            .join(format!("{}.{}", folder_name(&ID), extension))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

fn record() -> Result<Vec<u8>, BridgeError> {
    cleanup_record_bytes(
        ID,
        &folder_name(&ID),
        &ProcessIdentity {
            browser_pid: 42,
            creation_filetime: 1,
            image_path_sha256: ImagePathSha256::from_bytes([7; 32]),
        },
    )
}

fn restart(
    store: &mut WindowsCleanupStore,
    probe: &mut FakeProbe,
) -> Result<RestartProgress, BridgeError> {
    let (host, endpoint) = channel();
    drop(endpoint);
    OwnerBridge::new(
        host,
        FakeRandom::seeded(1),
        FakeClock::start(),
        BridgeConfig::new(None),
    )
    .start_restart_check(store, probe)
}

#[test]
fn every_observed_write_failure_preserves_pending_or_committed_recovery_input() -> TestResult {
    for fault in [
        Fault::Open(2),
        Fault::VolumeError(2),
        Fault::VolumeError(3),
        Fault::VolumeChanged(3),
        Fault::Write,
        Fault::Partial,
        Fault::Flush,
        Fault::PublishSourceOnly,
        Fault::PublishFinalOnly,
        Fault::PublishBoth,
        Fault::Open(3),
        Fault::VolumeError(4),
        Fault::VolumeChanged(4),
        Fault::Read,
        Fault::ChangedReadback,
    ] {
        let fixture = Fixture::new()?;
        let mut store = fixture.open(fault)?;
        assert!(store.write_record(&record()?).is_err());
        let pending = fixture.record_path("pending");
        let committed = fixture.record_path("pbcr");
        match fault {
            Fault::Open(2) | Fault::VolumeError(2) => {
                assert!(!pending.exists() && !committed.exists());
            }
            Fault::PublishFinalOnly
            | Fault::Open(3)
            | Fault::VolumeError(4)
            | Fault::VolumeChanged(4)
            | Fault::Read
            | Fault::ChangedReadback => assert!(!pending.exists() && committed.exists()),
            Fault::PublishBoth => assert!(pending.exists() && committed.exists()),
            _ => assert!(pending.exists() && !committed.exists()),
        }
        drop(store);
        let mut reopened = WindowsCleanupStore::open(fixture.0.clone())?;
        let observed = reopened.records()?;
        assert_eq!(
            observed.len(),
            usize::from(pending.exists()) + usize::from(committed.exists())
        );
        if matches!(fault, Fault::PublishBoth) {
            assert!(reopened.delete_record(&record()?).is_err());
            assert!(pending.exists() && committed.exists());
        }
    }
    Ok(())
}

#[test]
fn qualification_and_directory_access_errors_refuse_opening() -> TestResult {
    for fault in [Fault::Qualify, Fault::Open(1), Fault::VolumeError(1)] {
        let fixture = Fixture::new()?;
        assert!(fixture.open(fault).is_err());
    }
    let fixture = Fixture::new()?;
    let mut changed = fixture.open(Fault::VolumeChanged(2))?;
    assert!(changed.records().is_err());
    drop(changed);
    let mut store = fixture.open(Fault::None)?;
    store.write_record(&record()?)?;
    assert_eq!(store.records()?.len(), 1);
    Ok(())
}

struct Writer(Child);
impl Drop for Writer {
    fn drop(&mut self) {
        let _stopped = self.0.kill();
        let _reaped = self.0.wait();
    }
}

#[test]
fn interruption_writer_child() -> TestResult {
    let Some(root) = std::env::var_os("PIGLOR_CLEANUP_INTERRUPT_ROOT") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    let selected = std::env::var("PIGLOR_CLEANUP_INTERRUPT_STAGE")?;
    let stage = Stage::ALL
        .into_iter()
        .find(|stage| stage.name() == selected)
        .ok_or("unknown interruption stage")?;
    let mut store = Files::open_with(
        root.clone(),
        Box::new(Effects::new(&root, Fault::Pause(stage))),
    )?;
    store.write_record(&record()?)?;
    Err("writer did not stop at the selected publication stage".into())
}

#[test]
fn interrupted_writers_recover_through_the_public_restart_seam() -> TestResult {
    for stage in Stage::ALL {
        let fixture = Fixture::new()?;
        crate::create_private_directory(&fixture.0.join(folder_name(&ID)))?;
        let mut writer = Writer(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "adapter::store::tests::interruption_writer_child",
                    "--nocapture",
                ])
                .env("PIGLOR_CLEANUP_INTERRUPT_ROOT", &fixture.0)
                .env("PIGLOR_CLEANUP_INTERRUPT_STAGE", stage.name())
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if fs::read_to_string(fixture.0.join("checkpoint"))
                .is_ok_and(|value| value == stage.name())
            {
                break;
            }
            if let Some(status) = writer.0.try_wait()? {
                return Err(format!("writer exited before {}: {status}", stage.name()).into());
            }
            if Instant::now() >= deadline {
                return Err(format!("writer missed {} checkpoint", stage.name()).into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        writer.0.kill()?;
        let _status = writer.0.wait()?;
        drop(writer);
        let pending = fixture.record_path("pending");
        let committed = fixture.record_path("pbcr");
        assert_eq!(
            committed.exists(),
            matches!(stage, Stage::Published | Stage::Readback)
        );
        assert_eq!(pending.exists(), !committed.exists());
        let mut store = WindowsCleanupStore::open(fixture.0.clone())?;
        let mut probe = FakeProbe::new(vec![]);
        let result = restart(&mut store, &mut probe);
        if matches!(stage, Stage::Created | Stage::Partial) {
            assert_eq!(
                result,
                Err(BridgeError::Quarantine(QuarantineCode::StaleProcessPresent))
            );
            assert_eq!(probe.calls(), 0);
            assert!(pending.exists());
            assert!(fixture.0.join(folder_name(&ID)).is_dir());
        } else {
            assert!(matches!(result?, RestartProgress::Done { deferred: 0 }));
            assert_eq!(probe.calls(), 1);
            assert!(!pending.exists() && !committed.exists());
            assert!(!fixture.0.join(folder_name(&ID)).exists());
        }
    }
    Ok(())
}
