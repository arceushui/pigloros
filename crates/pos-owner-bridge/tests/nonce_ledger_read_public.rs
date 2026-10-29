#![cfg(any(test, feature = "test-support"))]
//! Existing-ledger reads through the public lock, with isolated private fixtures.
#![cfg(target_os = "linux")]

use std::fs::{self, Permissions};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

use pos_crypto::subject_nonce_ledger::{
    SubjectNonceLedgerRowV1, SubjectNonceLedgerV1, MAX_SUBJECT_NONCE_LEDGER_BYTES,
};
use pos_owner_bridge::encryptor_lock::linux::SubjectEncryptorLock;
use pos_owner_bridge::{BridgeError, UnavailableCode};
use rustix::fs::{flock, FlockOperation};

pub mod support;
use support::{private_directory, Sandbox};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LEDGER: &str = "subject-nonce-ledger.v1";
const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

fn write_private(path: &Path, bytes: &[u8]) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(())
}

fn assert_guard_retained(root: &Path) {
    assert_eq!(SubjectEncryptorLock::acquire(root).err(), Some(UNAVAILABLE));
}

#[test]
fn existing_canonical_bytes_compose_with_the_separate_snl1_codec() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let row = SubjectNonceLedgerRowV1 {
        owner_id: "subject:00000000000000000000000000000001".to_owned(),
        epoch: 1,
        root_material_digest: [9; 32],
        // Deliberately fixture metadata, never an established store binding.
        store_file_id: [7, 11],
        data_next: 12,
        bootstrap_next: 3,
    };
    let expected = SubjectNonceLedgerV1::new([row.clone()])?;
    let path = root.0.join("pigloros").join(LEDGER);
    write_private(&path, expected.as_bytes())?;
    let before = fs::metadata(&path)?;
    let bytes = guard.read_nonce_ledger_bytes()?;
    assert_eq!(bytes, expected.as_bytes());
    assert_eq!(
        SubjectNonceLedgerV1::from_bytes(&bytes)?.rows().next(),
        Some(&row)
    );
    assert_eq!(fs::read(&path)?, expected.as_bytes());
    let after = fs::metadata(path)?;
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_guard_retained(&root.0);
    Ok(())
}

#[test]
fn missing_ledger_is_not_created_and_failure_keeps_the_guard() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let leaf = root.0.join("pigloros");
    let path = leaf.join(LEDGER);
    assert_eq!(guard.read_nonce_ledger_bytes(), Err(UNAVAILABLE));
    assert!(!path.exists());
    assert_eq!(fs::read_dir(&leaf)?.count(), 1);
    assert_guard_retained(&root.0);
    drop(guard);
    let successor = SubjectEncryptorLock::acquire(&root.0)?;
    assert_eq!(successor.read_nonce_ledger_bytes(), Err(UNAVAILABLE));
    assert!(!path.exists());
    Ok(())
}

#[test]
fn complete_one_mib_is_returned_and_one_extra_byte_is_refused() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let path = root.0.join("pigloros").join(LEDGER);
    let mut bytes = vec![0x5a; MAX_SUBJECT_NONCE_LEDGER_BYTES];
    write_private(&path, &bytes)?;
    assert_eq!(guard.read_nonce_ledger_bytes()?, bytes);
    bytes.push(0xa5);
    write_private(&path, &bytes)?;
    assert_eq!(guard.read_nonce_ledger_bytes(), Err(UNAVAILABLE));
    assert_eq!(fs::read(path)?, bytes);
    assert_guard_retained(&root.0);
    Ok(())
}

#[test]
fn raw_transport_does_not_promote_empty_malformed_or_unknown_version_bytes() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let path = root.0.join("pigloros").join(LEDGER);
    for bytes in [b"".as_slice(), b"not SNL1", b"\x83\x44SNL1\x02\x80"] {
        write_private(&path, bytes)?;
        let read = guard.read_nonce_ledger_bytes()?;
        assert_eq!(read, bytes);
        assert!(SubjectNonceLedgerV1::from_bytes(&read).is_err());
        assert_eq!(fs::read(&path)?, bytes);
    }
    Ok(())
}

#[test]
fn unsafe_ledger_nodes_and_modes_are_rejected_without_replacement() -> TestResult {
    for kind in [
        "symlink",
        "hardlink",
        "directory",
        "fifo",
        "mode",
        "special-mode",
    ] {
        let root = Sandbox::new()?;
        let guard = SubjectEncryptorLock::acquire(&root.0)?;
        let path = root.0.join("pigloros").join(LEDGER);
        let original = root.0.join("original");
        write_private(&original, b"retained")?;
        match kind {
            "symlink" => symlink(&original, &path)?,
            "hardlink" => fs::hard_link(&original, &path)?,
            "directory" => private_directory(&path)?,
            "fifo" => rustix::fs::mknodat(
                rustix::fs::CWD,
                &path,
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR),
                0,
            )?,
            _ => {
                write_private(&path, b"retained ledger")?;
                let mode = if kind == "mode" { 0o640 } else { 0o1600 };
                fs::set_permissions(&path, Permissions::from_mode(mode))?;
            }
        }
        let before = fs::symlink_metadata(&path)?;
        assert_eq!(guard.read_nonce_ledger_bytes(), Err(UNAVAILABLE), "{kind}");
        let after = fs::symlink_metadata(&path)?;
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(before.mode(), after.mode());
        assert_eq!(fs::read(original)?, b"retained");
        assert_guard_retained(&root.0);
    }
    Ok(())
}

#[test]
fn ledger_contention_is_nonblocking_and_a_later_read_succeeds() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let path = root.0.join("pigloros").join(LEDGER);
    write_private(&path, b"unchanged bytes")?;
    let contender = fs::OpenOptions::new().read(true).write(true).open(&path)?;
    flock(&contender, FlockOperation::NonBlockingLockExclusive)?;
    assert_eq!(guard.read_nonce_ledger_bytes(), Err(UNAVAILABLE));
    assert_guard_retained(&root.0);
    assert_eq!(fs::read(&path)?, b"unchanged bytes");
    drop(contender);
    assert_eq!(guard.read_nonce_ledger_bytes()?, b"unchanged bytes");
    // The per-read ledger descriptor is closed, while the global guard survives.
    let successor = fs::OpenOptions::new().read(true).write(true).open(path)?;
    flock(&successor, FlockOperation::NonBlockingLockExclusive)?;
    assert_guard_retained(&root.0);
    Ok(())
}

#[test]
fn held_directory_is_close_on_exec_and_cannot_be_redirected_by_leaf_replacement() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let leaf = root.0.join("pigloros");
    let mut found = 0;
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        if fs::read_link(entry.path()).ok().as_deref() == Some(leaf.as_path()) {
            let info = fs::read_to_string(Path::new("/proc/self/fdinfo").join(entry.file_name()))?;
            let flags = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:"))
                .ok_or("missing directory descriptor flags")?;
            assert_ne!(
                u64::from_str_radix(flags.trim(), 8)?
                    & u64::from(rustix::fs::OFlags::CLOEXEC.bits()),
                0
            );
            found += 1;
        }
    }
    assert_eq!(found, 1);
    write_private(&leaf.join(LEDGER), b"held directory")?;
    // This probes read anchoring only. A recreated leaf can admit another lock
    // inode; this fixture does not establish production binding or exclusivity.
    let retained = root.0.join("retained");
    fs::rename(&leaf, &retained)?;
    private_directory(&leaf)?;
    write_private(&leaf.join(LEDGER), b"replacement directory")?;
    assert_eq!(guard.read_nonce_ledger_bytes()?, b"held directory");
    assert_eq!(fs::read(leaf.join(LEDGER))?, b"replacement directory");
    assert_eq!(fs::read(retained.join(LEDGER))?, b"held directory");
    Ok(())
}
