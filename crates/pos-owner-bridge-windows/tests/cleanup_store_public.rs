#![cfg(windows)]
#![forbid(unsafe_code)]

use std::fs;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pos_owner_bridge::channel::channel;
use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
use pos_owner_bridge::fake::host::FakeProbe;
use pos_owner_bridge::{
    cleanup_record_bytes, folder_name, BridgeConfig, BridgeError, CleanupStore, OwnerBridge,
    ProcessIdentity, QuarantineCode, RestartProgress,
};
use pos_owner_bridge_codec::{CeremonyId, ImagePathSha256, MAX_CLEANUP_RECORD_BYTES};
use pos_owner_bridge_windows::{create_private_directory, WindowsCleanupStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "piglor-cleanup-{}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        create_private_directory(&root)?;
        Ok(Self(root))
    }

    fn record_path(&self, id: u8, extension: &str) -> PathBuf {
        self.0
            .join("records")
            .join(format!("{}.{}", name(id), extension))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

fn name(id: u8) -> String {
    folder_name(&CeremonyId::from_bytes([id; 16]))
}

fn record(id: u8) -> Result<Vec<u8>, BridgeError> {
    cleanup_record_bytes(
        CeremonyId::from_bytes([id; 16]),
        &name(id),
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
fn cleanup_store_publishes_exact_records_and_recovery_uses_shared_provenance() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = WindowsCleanupStore::open(fixture.0.clone())?;
    let bytes = record(1)?;
    create_private_directory(&fixture.0.join(name(1)))?;
    store.write_record(&bytes)?;
    assert!(!fixture.record_path(1, "pending").exists());
    assert_eq!(fs::read(fixture.record_path(1, "pbcr"))?, bytes);
    assert_eq!(store.folders()?, vec![name(1)]);
    let mut restart_store = store.clone();
    assert_eq!(restart_store.records()?, vec![bytes.clone()]);
    // A clone used on the surface sees the exact provenance from restart admission.
    store.remove_folder(&name(1))?;
    store.delete_record(&bytes)?;
    assert!(restart_store.records()?.is_empty());
    store.remove_folder(&name(1))?;
    assert!(store.delete_record(&bytes).is_err());

    store.write_record(&record(2)?)?;
    create_private_directory(&fixture.0.join(name(2)))?;
    drop(restart_store);
    drop(store);
    let mut reopened = WindowsCleanupStore::open(fixture.0.clone())?;
    let mut probe = FakeProbe::new(vec![]);
    assert!(matches!(
        restart(&mut reopened, &mut probe)?,
        RestartProgress::Done { deferred: 0 }
    ));
    assert_eq!(probe.calls(), 1);
    assert!(!fixture.0.join(name(2)).exists());
    assert!(reopened.records()?.is_empty());
    Ok(())
}

#[test]
fn uncertain_pending_and_committed_pairs_are_never_deduplicated_or_bulk_deleted() -> TestResult {
    for different in [false, true] {
        let fixture = Fixture::new()?;
        let mut store = WindowsCleanupStore::open(fixture.0.clone())?;
        let bytes = record(3)?;
        store.write_record(&bytes)?;
        let pending = if different {
            // Both records decode and name the same ceremony folder. Only the
            // process identity differs, so admission must reject the collision
            // before probing rather than merely reject malformed CBOR.
            cleanup_record_bytes(
                CeremonyId::from_bytes([3; 16]),
                &name(3),
                &ProcessIdentity {
                    browser_pid: 43,
                    creation_filetime: 1,
                    image_path_sha256: ImagePathSha256::from_bytes([7; 32]),
                },
            )?
        } else {
            bytes.clone()
        };
        assert!(pos_owner_bridge_codec::decode_cleanup_record(&bytes).is_ok());
        assert!(pos_owner_bridge_codec::decode_cleanup_record(&pending).is_ok());
        assert_eq!(bytes != pending, different);
        fs::write(fixture.record_path(3, "pending"), &pending)?;
        let listed = store.records()?;
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&bytes) && listed.contains(&pending));
        let mut probe = FakeProbe::new(vec![]);
        assert_eq!(
            restart(&mut store, &mut probe),
            Err(BridgeError::Quarantine(QuarantineCode::StaleProcessPresent))
        );
        assert_eq!(probe.calls(), 0);
        if !different {
            assert!(store.delete_record(&bytes).is_err());
        }
        assert!(fixture.record_path(3, "pending").exists());
        assert!(fixture.record_path(3, "pbcr").exists());
    }
    Ok(())
}

#[test]
fn complete_pending_recovers_but_partial_and_oversized_records_quarantine() -> TestResult {
    for bytes in [
        record(4)?,
        vec![0xff],
        vec![0; MAX_CLEANUP_RECORD_BYTES + 20],
    ] {
        let fixture = Fixture::new()?;
        let mut store = WindowsCleanupStore::open(fixture.0.clone())?;
        fs::write(fixture.record_path(4, "pending"), &bytes)?;
        create_private_directory(&fixture.0.join(name(4)))?;
        assert_eq!(
            store.records()?[0].len(),
            bytes.len().min(MAX_CLEANUP_RECORD_BYTES + 1)
        );
        if bytes.len() > MAX_CLEANUP_RECORD_BYTES {
            let observed = store.records()?.remove(0);
            assert!(store.delete_record(&observed).is_err());
        }
        let mut probe = FakeProbe::new(vec![]);
        let result = restart(&mut store, &mut probe);
        if bytes == record(4)? {
            assert!(matches!(result?, RestartProgress::Done { deferred: 0 }));
            assert_eq!(probe.calls(), 1);
            assert!(!fixture.record_path(4, "pending").exists());
        } else {
            assert_eq!(
                result,
                Err(BridgeError::Quarantine(QuarantineCode::StaleProcessPresent))
            );
            assert_eq!(probe.calls(), 0);
            assert!(fixture.record_path(4, "pending").exists());
            assert!(fixture.0.join(name(4)).is_dir());
        }
    }
    Ok(())
}

#[test]
fn collisions_sharing_and_changed_deletion_content_preserve_metadata() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = WindowsCleanupStore::open(fixture.0.clone())?;
    let bytes = record(5)?;
    assert!(store.write_record(b"malformed").is_err());
    let foreign_folder = cleanup_record_bytes(
        CeremonyId::from_bytes([1; 16]),
        &name(2),
        &ProcessIdentity {
            browser_pid: 42,
            creation_filetime: 1,
            image_path_sha256: ImagePathSha256::from_bytes([7; 32]),
        },
    )?;
    assert!(store.write_record(&foreign_folder).is_err());
    store.write_record(&bytes)?;
    assert!(store.write_record(&bytes).is_err());
    assert_eq!(fs::read(fixture.record_path(5, "pbcr"))?, bytes);
    assert_eq!(fs::read(fixture.record_path(5, "pending"))?, bytes);
    fs::remove_file(fixture.record_path(5, "pending"))?;
    let path = fixture.record_path(5, "pbcr");
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)?;
    assert!(store.records().is_err());
    assert!(store.delete_record(&bytes).is_err());
    drop(held);
    assert_eq!(store.records()?, vec![bytes.clone()]);
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    fs::write(&path, &changed)?;
    assert!(store.delete_record(&bytes).is_err());
    assert_eq!(fs::read(&path)?, changed);
    assert!(store.remove_folder("../escape").is_err());
    Ok(())
}

#[test]
fn weakened_root_or_record_directory_refuses_constructor_and_live_operations() -> TestResult {
    for records in [false, true] {
        let fixture = Fixture::new()?;
        let mut store = WindowsCleanupStore::open(fixture.0.clone())?;
        let bytes = record(10)?;
        store.write_record(&bytes)?;
        let path = if records {
            fixture.0.join("records")
        } else {
            fixture.0.clone()
        };
        let broadened = Command::new("icacls.exe")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:(RX)"])
            .output()?;
        assert!(broadened.status.success());
        assert!(WindowsCleanupStore::open(fixture.0.clone()).is_err());
        assert!(store.records().is_err());
        assert!(store.folders().is_err());
        assert!(store.write_record(&record(11)?).is_err());
        assert!(store.remove_folder(&name(10)).is_err());
        assert!(store.delete_record(&bytes).is_err());
        assert!(fixture.record_path(10, "pbcr").exists());
        let restored = Command::new("icacls.exe")
            .arg(&path)
            .args(["/remove:g", "*S-1-1-0"])
            .output()?;
        assert!(restored.status.success());
        assert_eq!(store.records()?, vec![bytes.clone()]);
        store.delete_record(&bytes)?;
    }
    Ok(())
}

#[test]
fn recognized_directory_and_malformed_names_refuse_whole_store_scan() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = WindowsCleanupStore::open(fixture.0.clone())?;
    for file in [
        "bad.pbcr",
        "ABCDEF0123456789abcdef0123456789.pbcr",
        "01010101010101010101010101010101.PBCR",
    ] {
        let path = fixture.0.join("records").join(file);
        fs::write(&path, record(1)?)?;
        assert!(store.records().is_err());
        fs::remove_file(path)?;
    }
    let directory = fixture.record_path(1, "pending");
    fs::create_dir(&directory)?;
    assert!(store.records().is_err());
    fs::remove_dir(directory)?;
    fs::write(fixture.0.join("records/notes.txt"), b"not a cleanup record")?;
    fs::write(fixture.0.join("records/notes"), b"no recognized suffix")?;
    assert!(store.records()?.is_empty());
    assert!(WindowsCleanupStore::open(Path::new("relative").to_path_buf()).is_err());
    assert!(WindowsCleanupStore::open(fixture.0.join("..")).is_err());
    assert!(WindowsCleanupStore::open(Path::new(r"\\server\share\state").to_path_buf()).is_err());
    assert!(WindowsCleanupStore::open(Path::new(r"\\.\pipe\state").to_path_buf()).is_err());
    Ok(())
}

#[test]
fn folder_first_sharing_failure_defers_record_and_a_fresh_restart_retries() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = WindowsCleanupStore::open(fixture.0.clone())?;
    create_private_directory(&fixture.0.join(name(6)))?;
    let child = fixture.0.join(name(6)).join("held");
    fs::write(&child, b"held open by the fixture")?;
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&child)?;
    store.write_record(&record(6)?)?;
    let mut probe = FakeProbe::new(vec![]);
    assert!(matches!(
        restart(&mut store, &mut probe)?,
        RestartProgress::Done { deferred: 1 }
    ));
    assert!(fixture.record_path(6, "pbcr").exists());
    assert!(child.exists());
    drop(held);
    assert!(matches!(
        restart(&mut store, &mut probe)?,
        RestartProgress::Done { deferred: 0 }
    ));
    assert!(!fixture.record_path(6, "pbcr").exists());
    assert!(!fixture.0.join(name(6)).exists());
    Ok(())
}

#[test]
fn record_and_folder_junctions_never_remove_the_external_target() -> TestResult {
    let outside = Fixture::new()?;
    fs::write(outside.0.join("keep"), b"outside the cleanup namespace")?;
    for record_link in [false, true] {
        let fixture = Fixture::new()?;
        let mut store = WindowsCleanupStore::open(fixture.0.clone())?;
        let link = if record_link {
            fixture.record_path(7, "pbcr")
        } else {
            fixture.0.join(name(7))
        };
        let output = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside.0)
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if record_link {
            assert!(store.records().is_err());
        } else {
            assert!(store.folders().is_err());
            assert!(store.remove_folder(&name(7)).is_err());
        }
        assert_eq!(
            fs::read(outside.0.join("keep"))?,
            b"outside the cleanup namespace"
        );
    }
    Ok(())
}

#[test]
fn deletion_requires_one_remaining_exact_path_from_prior_scan_or_write() -> TestResult {
    let fixture = Fixture::new()?;
    let mut store = WindowsCleanupStore::open(fixture.0.clone())?;
    let bytes = record(8)?;
    fs::write(fixture.record_path(8, "pbcr"), &bytes)?;
    assert!(store.delete_record(&bytes).is_err());
    fs::write(fixture.record_path(8, "pending"), &bytes)?;
    assert_eq!(store.records()?.len(), 2);
    assert!(store.delete_record(&bytes).is_err());
    fs::remove_file(fixture.record_path(8, "pending"))?;
    store.delete_record(&bytes)?;
    store.write_record(&record(9)?)?;
    fs::remove_file(fixture.record_path(9, "pbcr"))?;
    assert!(store.delete_record(&record(9)?).is_err());
    Ok(())
}
