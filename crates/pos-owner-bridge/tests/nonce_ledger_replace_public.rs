#![cfg(any(test, feature = "test-support"))]
//! Existing-ledger replacement and orphan recovery through public test APIs.
#![cfg(target_os = "linux")]

use std::fs::{self, Permissions};
use std::io::Read as _;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

use pos_crypto::subject_key::SubjectKeyUseV1;
use pos_crypto::subject_nonce_ledger::{
    SubjectNonceLedgerRowV1, SubjectNonceLedgerV1, MAX_SUBJECT_NONCE_LEDGER_BYTES,
};
use pos_owner_bridge::encryptor_lock::linux::SubjectEncryptorLock;
use pos_owner_bridge::{BridgeError, UnavailableCode};
use rustix::fs::{flock, FlockOperation};

pub mod support;
use support::{private_directory, write_private, Sandbox};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LEDGER: &str = "subject-nonce-ledger.v1";
const TEMPORARY: &str = "subject-nonce-ledger.v1.tmp";
const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

fn ledger() -> TestResult<(SubjectNonceLedgerV1, SubjectNonceLedgerRowV1)> {
    let row = SubjectNonceLedgerRowV1 {
        owner_id: "subject:00000000000000000000000000000001".to_owned(),
        epoch: 1,
        root_material_digest: [9; 32],
        store_file_id: [7, 11],
        data_next: 12,
        bootstrap_next: 3,
    };
    Ok((SubjectNonceLedgerV1::new([row.clone()])?, row))
}

fn assert_guard_retained(root: &Path) {
    assert_eq!(SubjectEncryptorLock::acquire(root).err(), Some(UNAVAILABLE));
}

#[test]
fn canonical_candidate_replaces_the_inode_without_changing_the_open_old_image() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let leaf = root.0.join("pigloros");
    let path = leaf.join(LEDGER);
    let (old, row) = ledger()?;
    write_private(&path, old.as_bytes())?;
    let mut original = fs::File::open(&path)?;
    let before = original.metadata()?;
    let candidate = old.advance_counter(&row, SubjectKeyUseV1::Data)?;
    guard.replace_nonce_ledger_bytes(candidate.as_bytes())?;
    assert_eq!(guard.read_nonce_ledger_bytes()?, candidate.as_bytes());
    let mut retained = Vec::new();
    original.read_to_end(&mut retained)?;
    assert_eq!(retained, old.as_bytes());
    let after = fs::metadata(&path)?;
    assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(after.mode() & 0o7777, 0o600);
    assert_eq!(after.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(after.nlink(), 1);
    let decoded = SubjectNonceLedgerV1::from_bytes(&fs::read(&path)?)?;
    let mut expected = row;
    expected.data_next += 1;
    assert_eq!(decoded.rows().next(), Some(&expected));
    assert!(!leaf.join(TEMPORARY).exists());
    assert_guard_retained(&root.0);
    Ok(())
}

#[test]
fn missing_ledger_is_never_initialized_by_replacement() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let (candidate, _) = ledger()?;
    assert_eq!(
        guard.replace_nonce_ledger_bytes(candidate.as_bytes()),
        Err(UNAVAILABLE)
    );
    let leaf = root.0.join("pigloros");
    assert!(!leaf.join(LEDGER).exists());
    assert!(!leaf.join(TEMPORARY).exists());
    assert_eq!(fs::read_dir(leaf)?.count(), 1);
    assert_guard_retained(&root.0);
    Ok(())
}

#[test]
fn raw_byte_bound_is_exact_and_over_limit_does_not_touch_the_existing_file() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let leaf = root.0.join("pigloros");
    let path = leaf.join(LEDGER);
    write_private(&path, ledger()?.0.as_bytes())?;
    // This measures transport bytes, not SNL1 grammar or reservation authority.
    let mut bytes = vec![0x5a; MAX_SUBJECT_NONCE_LEDGER_BYTES];
    guard.replace_nonce_ledger_bytes(&bytes)?;
    assert_eq!(guard.read_nonce_ledger_bytes()?, bytes);
    let before = fs::metadata(&path)?;
    bytes.push(0xa5);
    assert_eq!(guard.replace_nonce_ledger_bytes(&bytes), Err(UNAVAILABLE));
    assert_eq!(fs::read(&path)?, bytes[..MAX_SUBJECT_NONCE_LEDGER_BYTES]);
    assert_eq!(fs::metadata(path)?.ino(), before.ino());
    assert!(!leaf.join(TEMPORARY).exists());
    assert_guard_retained(&root.0);
    Ok(())
}

#[test]
fn unsafe_existing_ledgers_are_refused_without_creating_staging_state() -> TestResult {
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
        let leaf = root.0.join("pigloros");
        let path = leaf.join(LEDGER);
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
        assert_eq!(
            guard.replace_nonce_ledger_bytes(ledger()?.0.as_bytes()),
            Err(UNAVAILABLE),
            "{kind}"
        );
        let after = fs::symlink_metadata(&path)?;
        assert_eq!(
            (before.dev(), before.ino(), before.mode()),
            (after.dev(), after.ino(), after.mode())
        );
        assert_eq!(fs::read(original)?, b"retained");
        assert!(!leaf.join(TEMPORARY).exists());
        assert_guard_retained(&root.0);
    }
    Ok(())
}

#[test]
fn contention_and_an_occupied_staging_slot_are_non_destructive() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let leaf = root.0.join("pigloros");
    let path = leaf.join(LEDGER);
    let (old, row) = ledger()?;
    write_private(&path, old.as_bytes())?;
    let contender = fs::OpenOptions::new().read(true).write(true).open(&path)?;
    flock(&contender, FlockOperation::NonBlockingLockExclusive)?;
    let candidate = old.advance_counter(&row, SubjectKeyUseV1::Data)?;
    assert_eq!(
        guard.replace_nonce_ledger_bytes(candidate.as_bytes()),
        Err(UNAVAILABLE)
    );
    assert!(!leaf.join(TEMPORARY).exists());
    drop(contender);
    let temporary = leaf.join(TEMPORARY);
    write_private(&temporary, b"occupied")?;
    assert_eq!(
        guard.replace_nonce_ledger_bytes(candidate.as_bytes()),
        Err(UNAVAILABLE)
    );
    assert_eq!(fs::read(&temporary)?, b"occupied");
    assert_eq!(fs::read(&path)?, old.as_bytes());
    assert_guard_retained(&root.0);
    drop(guard);
    let reopened = SubjectEncryptorLock::acquire(&root.0)?;
    assert!(!temporary.exists());
    reopened.replace_nonce_ledger_bytes(candidate.as_bytes())?;
    assert_eq!(reopened.read_nonce_ledger_bytes()?, candidate.as_bytes());
    Ok(())
}

#[test]
fn unsafe_or_busy_orphans_are_refused_and_unrelated_files_survive_recovery() -> TestResult {
    for kind in ["symlink", "hardlink", "directory", "fifo", "mode", "busy"] {
        let root = Sandbox::new()?;
        let guard = SubjectEncryptorLock::acquire(&root.0)?;
        let leaf = root.0.join("pigloros");
        let ledger_path = leaf.join(LEDGER);
        let temporary = leaf.join(TEMPORARY);
        let (old, _) = ledger()?;
        write_private(&ledger_path, old.as_bytes())?;
        let unrelated = leaf.join("unrelated.tmp");
        write_private(&unrelated, b"retained")?;
        match kind {
            "symlink" => symlink(&ledger_path, &temporary)?,
            "hardlink" => fs::hard_link(&ledger_path, &temporary)?,
            "directory" => private_directory(&temporary)?,
            "fifo" => rustix::fs::mknodat(
                rustix::fs::CWD,
                &temporary,
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR),
                0,
            )?,
            _ => write_private(&temporary, b"orphan")?,
        }
        if kind == "mode" {
            fs::set_permissions(&temporary, Permissions::from_mode(0o640))?;
        }
        let busy = if kind == "busy" {
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&temporary)?;
            flock(&file, FlockOperation::NonBlockingLockExclusive)?;
            Some(file)
        } else {
            None
        };
        let before = fs::symlink_metadata(&temporary)?;
        drop(guard);
        assert_eq!(
            SubjectEncryptorLock::acquire(&root.0).err(),
            Some(UNAVAILABLE),
            "{kind}"
        );
        assert_eq!(fs::symlink_metadata(&temporary)?.ino(), before.ino());
        assert_eq!(fs::read(&ledger_path)?, old.as_bytes());
        assert_eq!(fs::read(&unrelated)?, b"retained");
        drop(busy);
        if kind == "busy" {
            let reopened = SubjectEncryptorLock::acquire(&root.0)?;
            assert!(!temporary.exists());
            assert_eq!(reopened.read_nonce_ledger_bytes()?, old.as_bytes());
            assert_eq!(fs::read(unrelated)?, b"retained");
        }
    }
    Ok(())
}

#[test]
fn replacement_stays_anchored_to_the_held_directory() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let leaf = root.0.join("pigloros");
    let (old, row) = ledger()?;
    write_private(&leaf.join(LEDGER), old.as_bytes())?;
    let retained = root.0.join("retained");
    fs::rename(&leaf, &retained)?;
    private_directory(&leaf)?;
    write_private(&leaf.join(LEDGER), b"replacement directory")?;
    let candidate = old.advance_counter(&row, SubjectKeyUseV1::Data)?;
    guard.replace_nonce_ledger_bytes(candidate.as_bytes())?;
    assert_eq!(fs::read(retained.join(LEDGER))?, candidate.as_bytes());
    assert_eq!(fs::read(leaf.join(LEDGER))?, b"replacement directory");
    // This does not prove global exclusivity after replacing the directory.
    Ok(())
}
