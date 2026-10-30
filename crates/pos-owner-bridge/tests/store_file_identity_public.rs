#![cfg(any(test, feature = "test-support"))]
//! Candidate descriptor identity, not SQLite qualification or store authority.
#![cfg(target_os = "linux")]

use std::fs::{self, File, Permissions};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

use pos_crypto::subject_nonce_ledger::{SubjectNonceLedgerRowV1, SubjectNonceLedgerV1};
use pos_owner_bridge::encryptor_lock::linux::store_file_id;
use pos_owner_bridge::{BridgeError, UnavailableCode};
use rustix::fs::{self as descriptor_fs, FileType, Mode, OFlags, CWD};

pub mod support;
use support::{write_private, Sandbox};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

fn candidate(root: &Sandbox) -> TestResult<File> {
    let path = root.0.join("store");
    write_private(&path, b"candidate bytes")?;
    Ok(File::open(path)?)
}

#[test]
fn private_regular_descriptor_matches_independent_metadata_and_the_snl1_pair() -> TestResult {
    let root = Sandbox::new()?;
    let file = candidate(&root)?;
    let metadata = file.metadata()?;
    let identity = store_file_id(&file)?;
    assert_eq!(identity, [metadata.dev(), metadata.ino()]);
    let row = SubjectNonceLedgerRowV1 {
        owner_id: "subject:00000000000000000000000000000001".to_owned(),
        epoch: 1,
        root_material_digest: [9; 32],
        store_file_id: identity,
        data_next: 12,
        bootstrap_next: 3,
    };
    let ledger = SubjectNonceLedgerV1::new([row.clone()])?;
    let decoded = SubjectNonceLedgerV1::from_bytes(ledger.as_bytes())?;
    assert_eq!(decoded.rows().next(), Some(&row));
    assert_eq!(fs::read(root.0.join("store"))?, b"candidate bytes");
    assert_eq!(file.metadata()?.mode(), metadata.mode());
    Ok(())
}

#[test]
fn equal_byte_copies_differ_while_inode_aliases_and_duplicates_match() -> TestResult {
    let root = Sandbox::new()?;
    let file = candidate(&root)?;
    let identity = store_file_id(&file)?;
    let path = root.0.join("store");
    let copy = root.0.join("copy");
    fs::copy(&path, &copy)?;
    assert_eq!(fs::read(&path)?, fs::read(&copy)?);
    assert_ne!(store_file_id(&File::open(copy)?)?, identity);

    let alias = root.0.join("alias");
    fs::hard_link(&path, &alias)?;
    assert_eq!(store_file_id(&File::open(alias)?)?, identity);
    let link = root.0.join("link");
    symlink(&path, &link)?;
    assert_eq!(store_file_id(&File::open(link)?)?, identity);
    let duplicate = file.try_clone()?;
    assert_eq!(store_file_id(&duplicate)?, identity);
    assert_eq!(file.metadata()?.nlink(), 2);
    Ok(())
}

#[test]
fn rename_and_path_replacement_do_not_redirect_a_held_descriptor() -> TestResult {
    let root = Sandbox::new()?;
    let file = candidate(&root)?;
    let identity = store_file_id(&file)?;
    let path = root.0.join("store");
    let retained = root.0.join("retained");
    fs::rename(&path, &retained)?;
    write_private(&path, b"replacement bytes")?;
    assert_eq!(store_file_id(&file)?, identity);
    assert_ne!(store_file_id(&File::open(path)?)?, identity);
    assert_eq!(fs::read(retained)?, b"candidate bytes");
    Ok(())
}

#[test]
fn current_permissions_are_rechecked_and_left_unchanged() -> TestResult {
    let root = Sandbox::new()?;
    let file = candidate(&root)?;
    let identity = store_file_id(&file)?;
    let path = root.0.join("store");
    for mode in [0, 0o400, 0o640, 0o644, 0o1600] {
        fs::set_permissions(&path, Permissions::from_mode(mode))?;
        assert_eq!(store_file_id(&file), Err(UNAVAILABLE), "{mode:o}");
        assert_eq!(file.metadata()?.mode() & 0o7777, mode);
    }
    fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    assert_eq!(store_file_id(&file)?, identity);
    Ok(())
}

#[test]
fn nonregular_descriptors_are_refused_including_an_open_symlink_itself() -> TestResult {
    let root = Sandbox::new()?;
    let file = candidate(&root)?;
    assert_eq!(store_file_id(&File::open(&root.0)?), Err(UNAVAILABLE));
    let fifo = root.0.join("fifo");
    descriptor_fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0)?;
    let descriptor = descriptor_fs::openat(
        CWD,
        &fifo,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    assert_eq!(store_file_id(&descriptor), Err(UNAVAILABLE));

    let link = root.0.join("link");
    symlink(root.0.join("store"), &link)?;
    let descriptor = descriptor_fs::openat(
        CWD,
        &link,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    assert_eq!(store_file_id(&descriptor), Err(UNAVAILABLE));
    assert_eq!(store_file_id(&file)?, store_file_id(&File::open(link)?)?);
    Ok(())
}
