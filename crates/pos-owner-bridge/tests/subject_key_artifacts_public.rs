#![cfg(any(test, feature = "test-support"))]
//! ADR-137 P4 `subject-keys.v1` admission, staging, replacement and inventory.
#![cfg(target_os = "linux")]

use std::fs::{self, Permissions};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use pos_owner_bridge::encryptor_lock::linux::{
    SubjectEncryptorLock, SubjectKeyArtifactContent, SubjectKeyArtifactEntry,
    SubjectKeyArtifactKind, SubjectKeyArtifactName, MAX_SUBJECT_KEY_ARTIFACT_BYTES,
    MAX_SUBJECT_KEY_ARTIFACT_ENTRIES,
};
use pos_owner_bridge::{BridgeError, UnavailableCode};
use rustix::fs::{flock, FlockOperation};

pub mod support;
use support::{private_directory, write_private, Sandbox};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const DIRECTORY: &str = "subject-keys.v1";
const OWNER: &str = "subject:000102030405060708090a0b0c0d0e0f";
const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

fn name(kind: SubjectKeyArtifactKind, epoch: u64) -> TestResult<SubjectKeyArtifactName> {
    SubjectKeyArtifactName::new(kind, OWNER, epoch)
        .ok_or_else(|| "valid fixture name refused".into())
}

fn wrap() -> TestResult<SubjectKeyArtifactName> {
    name(SubjectKeyArtifactKind::Wrap, 3)
}

fn binding() -> TestResult<SubjectKeyArtifactName> {
    name(SubjectKeyArtifactKind::Binding, 3)
}

fn acquire() -> TestResult<(Sandbox, SubjectEncryptorLock, PathBuf)> {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let directory = root.0.join("pigloros").join(DIRECTORY);
    Ok((root, guard, directory))
}

fn admitted() -> TestResult<(Sandbox, SubjectEncryptorLock, PathBuf)> {
    let (root, guard, directory) = acquire()?;
    assert!(guard.list_and_read_subject_key_artifacts()?.is_empty());
    Ok((root, guard, directory))
}

fn regular(path: &Path, bytes: &[u8]) -> TestResult<SubjectKeyArtifactContent> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(SubjectKeyArtifactContent::Regular {
        identity: [metadata.dev(), metadata.ino()],
        bytes: bytes.to_vec(),
    })
}

fn entry_names(guard: &SubjectEncryptorLock) -> TestResult<Vec<Vec<u8>>> {
    Ok(guard
        .list_and_read_subject_key_artifacts()?
        .into_iter()
        .map(|entry| entry.name)
        .collect())
}

fn assert_guard_retained(root: &Path) {
    assert_eq!(SubjectEncryptorLock::acquire(root).err(), Some(UNAVAILABLE));
}

fn fifo(path: &Path) -> TestResult {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR),
        0,
    )
    .map_err(Into::into)
}

#[test]
fn a_missing_directory_is_created_private_and_an_existing_one_is_reused() -> TestResult {
    let (root, guard, directory) = acquire()?;
    assert!(!directory.exists());
    assert!(guard.list_and_read_subject_key_artifacts()?.is_empty());
    let metadata = fs::symlink_metadata(&directory)?;
    assert!(metadata.is_dir());
    assert_eq!(metadata.mode() & 0o7777, 0o700);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    guard.stage_subject_key_artifact(&wrap()?, b"wrap bytes")?;
    assert_eq!(fs::symlink_metadata(&directory)?.ino(), metadata.ino());
    assert_guard_retained(&root.0);
    Ok(())
}

#[test]
fn staging_creates_the_canonical_private_file_without_a_temporary() -> TestResult {
    let (root, guard, directory) = acquire()?;
    let (wrap, binding) = (wrap()?, binding()?);
    guard.stage_subject_key_artifact(&wrap, b"wrap bytes")?;
    guard.stage_subject_key_artifact(&binding, b"binding bytes")?;
    for (staged, bytes) in [(&wrap, &b"wrap bytes"[..]), (&binding, b"binding bytes")] {
        let path = directory.join(staged.canonical());
        assert_eq!(fs::read(&path)?, bytes);
        let metadata = fs::symlink_metadata(&path)?;
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.nlink(), 1);
        assert!(!directory.join(staged.temporary()).exists());
    }
    assert_eq!(fs::read_dir(&directory)?.count(), 2);
    assert_guard_retained(&root.0);
    Ok(())
}

#[test]
fn unsafe_artifact_directories_are_refused_by_every_operation() -> TestResult {
    for kind in [
        "symlink",
        "file",
        "fifo",
        "group-mode",
        "sticky-mode",
        "owner-mode",
    ] {
        let (root, guard, directory) = acquire()?;
        let target = root.0.join("target");
        private_directory(&target)?;
        match kind {
            "symlink" => symlink(&target, &directory)?,
            "file" => write_private(&directory, b"not a directory")?,
            "fifo" => fifo(&directory)?,
            _ => {
                private_directory(&directory)?;
                let mode = match kind {
                    "group-mode" => 0o750,
                    "sticky-mode" => 0o1700,
                    _ => 0o500,
                };
                fs::set_permissions(&directory, Permissions::from_mode(mode))?;
            }
        }
        let before = fs::symlink_metadata(&directory)?;
        assert_eq!(
            guard.list_and_read_subject_key_artifacts(),
            Err(UNAVAILABLE),
            "{kind}"
        );
        assert_eq!(
            guard.stage_subject_key_artifact(&wrap()?, b"wrap bytes"),
            Err(UNAVAILABLE),
            "{kind}"
        );
        assert_eq!(
            guard.replace_subject_key_artifact(&binding()?, b"binding bytes"),
            Err(UNAVAILABLE),
            "{kind}"
        );
        let after = fs::symlink_metadata(&directory)?;
        assert_eq!(
            (before.ino(), before.mode()),
            (after.ino(), after.mode()),
            "{kind}"
        );
        assert_eq!(fs::read_dir(&target)?.count(), 0, "{kind}");
        assert_guard_retained(&root.0);
    }
    Ok(())
}

#[test]
fn staging_never_replaces_an_existing_canonical_entry() -> TestResult {
    for kind in ["file", "symlink", "directory"] {
        let (root, guard, directory) = admitted()?;
        let wrap = wrap()?;
        let canonical = directory.join(wrap.canonical());
        let elsewhere = root.0.join("elsewhere");
        write_private(&elsewhere, b"elsewhere")?;
        match kind {
            "file" => write_private(&canonical, b"existing")?,
            "symlink" => symlink(&elsewhere, &canonical)?,
            _ => private_directory(&canonical)?,
        }
        let before = fs::symlink_metadata(&canonical)?;
        assert_eq!(
            guard.stage_subject_key_artifact(&wrap, b"new wrap"),
            Err(UNAVAILABLE),
            "{kind}"
        );
        let after = fs::symlink_metadata(&canonical)?;
        assert_eq!(
            (before.ino(), before.mode()),
            (after.ino(), after.mode()),
            "{kind}"
        );
        if kind == "file" {
            assert_eq!(fs::read(&canonical)?, b"existing");
        }
        assert_eq!(fs::read(&elsewhere)?, b"elsewhere");
        assert!(!directory.join(wrap.temporary()).exists(), "{kind}");
        assert_eq!(fs::read_dir(&directory)?.count(), 1, "{kind}");
    }
    Ok(())
}

#[test]
fn an_existing_temporary_entry_blocks_staging_and_replacement_untouched() -> TestResult {
    for kind in ["file", "symlink"] {
        let (root, guard, directory) = admitted()?;
        let binding = binding()?;
        let temporary = directory.join(binding.temporary());
        let elsewhere = root.0.join("elsewhere");
        write_private(&elsewhere, b"elsewhere")?;
        match kind {
            "file" => write_private(&temporary, b"occupied")?,
            _ => symlink(&elsewhere, &temporary)?,
        }
        assert_eq!(
            guard.stage_subject_key_artifact(&binding, b"new binding"),
            Err(UNAVAILABLE),
            "{kind}"
        );
        assert!(!directory.join(binding.canonical()).exists());
        write_private(&directory.join(binding.canonical()), b"existing binding")?;
        assert_eq!(
            guard.replace_subject_key_artifact(&binding, b"new binding"),
            Err(UNAVAILABLE),
            "{kind}"
        );
        assert_eq!(
            fs::read(directory.join(binding.canonical()))?,
            b"existing binding"
        );
        if kind == "file" {
            assert_eq!(fs::read(&temporary)?, b"occupied");
        } else {
            assert!(fs::symlink_metadata(&temporary)?.is_symlink());
        }
        assert_eq!(fs::read(&elsewhere)?, b"elsewhere");
    }
    Ok(())
}

#[test]
fn the_write_bound_is_exact_on_both_sides() -> TestResult {
    let (_root, guard, directory) = admitted()?;
    let mut bytes = vec![0x5a; MAX_SUBJECT_KEY_ARTIFACT_BYTES];
    let binding = binding()?;
    guard.stage_subject_key_artifact(&binding, &bytes)?;
    assert_eq!(fs::read(directory.join(binding.canonical()))?, bytes);
    guard.replace_subject_key_artifact(&binding, &bytes)?;
    let before = fs::symlink_metadata(directory.join(binding.canonical()))?;
    bytes.push(0xa5);
    assert_eq!(
        guard.replace_subject_key_artifact(&binding, &bytes),
        Err(UNAVAILABLE)
    );
    let wrap = wrap()?;
    assert_eq!(
        guard.stage_subject_key_artifact(&wrap, &bytes),
        Err(UNAVAILABLE)
    );
    let after = fs::symlink_metadata(directory.join(binding.canonical()))?;
    assert_eq!(before.ino(), after.ino());
    assert_eq!(
        fs::read(directory.join(binding.canonical()))?,
        bytes[..MAX_SUBJECT_KEY_ARTIFACT_BYTES]
    );
    assert_eq!(fs::read_dir(&directory)?.count(), 1);
    Ok(())
}

#[test]
fn replacing_a_binding_swaps_the_inode_atomically() -> TestResult {
    let (root, guard, directory) = admitted()?;
    let binding = binding()?;
    guard.stage_subject_key_artifact(&binding, b"sign count 1")?;
    let path = directory.join(binding.canonical());
    let before = fs::symlink_metadata(&path)?;
    guard.replace_subject_key_artifact(&binding, b"sign count 2")?;
    assert_eq!(fs::read(&path)?, b"sign count 2");
    let after = fs::symlink_metadata(&path)?;
    assert_ne!(before.ino(), after.ino());
    assert_eq!(after.mode() & 0o7777, 0o600);
    assert_eq!(after.nlink(), 1);
    assert!(!directory.join(binding.temporary()).exists());
    assert_eq!(fs::read_dir(&directory)?.count(), 1);
    assert_guard_retained(&root.0);
    Ok(())
}

#[test]
fn replacement_never_creates_a_binding_or_touches_a_wrap() -> TestResult {
    let (_root, guard, directory) = admitted()?;
    let binding = binding()?;
    assert_eq!(
        guard.replace_subject_key_artifact(&binding, b"binding"),
        Err(UNAVAILABLE)
    );
    assert_eq!(fs::read_dir(&directory)?.count(), 0);
    let wrap = wrap()?;
    guard.stage_subject_key_artifact(&wrap, b"wrap")?;
    assert_eq!(
        guard.replace_subject_key_artifact(&wrap, b"other wrap"),
        Err(UNAVAILABLE)
    );
    assert_eq!(fs::read(directory.join(wrap.canonical()))?, b"wrap");
    assert!(!directory.join(wrap.temporary()).exists());
    Ok(())
}

#[test]
fn unsafe_or_busy_existing_bindings_are_not_replaced() -> TestResult {
    for kind in ["symlink", "hardlink", "directory", "fifo", "mode", "busy"] {
        let (root, guard, directory) = admitted()?;
        let binding = binding()?;
        let path = directory.join(binding.canonical());
        let original = root.0.join("original");
        write_private(&original, b"retained")?;
        match kind {
            "symlink" => symlink(&original, &path)?,
            "hardlink" => fs::hard_link(&original, &path)?,
            "directory" => private_directory(&path)?,
            "fifo" => fifo(&path)?,
            _ => write_private(&path, b"retained binding")?,
        }
        if kind == "mode" {
            fs::set_permissions(&path, Permissions::from_mode(0o640))?;
        }
        let busy = if kind == "busy" {
            let file = fs::OpenOptions::new().read(true).write(true).open(&path)?;
            flock(&file, FlockOperation::NonBlockingLockExclusive)?;
            Some(file)
        } else {
            None
        };
        let before = fs::symlink_metadata(&path)?;
        assert_eq!(
            guard.replace_subject_key_artifact(&binding, b"new binding"),
            Err(UNAVAILABLE),
            "{kind}"
        );
        let after = fs::symlink_metadata(&path)?;
        assert_eq!(
            (before.ino(), before.mode()),
            (after.ino(), after.mode()),
            "{kind}"
        );
        assert_eq!(fs::read(&original)?, b"retained");
        assert!(!directory.join(binding.temporary()).exists(), "{kind}");
        drop(busy);
    }
    Ok(())
}

#[test]
fn inventory_reads_every_regular_file_and_reports_other_entries_sorted() -> TestResult {
    let (root, guard, directory) = admitted()?;
    let (wrap, binding) = (wrap()?, binding()?);
    guard.stage_subject_key_artifact(&wrap, b"wrap bytes")?;
    guard.stage_subject_key_artifact(&binding, b"binding bytes")?;
    let elsewhere = root.0.join("elsewhere");
    write_private(&elsewhere, b"never followed")?;
    write_private(&directory.join("unrelated"), b"unrelated bytes")?;
    write_private(&directory.join(wrap.temporary()), b"")?;
    symlink(&elsewhere, directory.join("link"))?;
    private_directory(&directory.join("nested"))?;
    fifo(&directory.join("pipe"))?;
    let listed = guard.list_and_read_subject_key_artifacts()?;
    let expected = vec![
        SubjectKeyArtifactEntry {
            name: binding.canonical().into_bytes(),
            content: regular(&directory.join(binding.canonical()), b"binding bytes")?,
        },
        SubjectKeyArtifactEntry {
            name: b"link".to_vec(),
            content: SubjectKeyArtifactContent::NonRegular,
        },
        SubjectKeyArtifactEntry {
            name: b"nested".to_vec(),
            content: SubjectKeyArtifactContent::NonRegular,
        },
        SubjectKeyArtifactEntry {
            name: b"pipe".to_vec(),
            content: SubjectKeyArtifactContent::NonRegular,
        },
        SubjectKeyArtifactEntry {
            name: b"unrelated".to_vec(),
            content: regular(&directory.join("unrelated"), b"unrelated bytes")?,
        },
        SubjectKeyArtifactEntry {
            name: wrap.canonical().into_bytes(),
            content: regular(&directory.join(wrap.canonical()), b"wrap bytes")?,
        },
        SubjectKeyArtifactEntry {
            name: wrap.temporary().into_bytes(),
            content: regular(&directory.join(wrap.temporary()), b"")?,
        },
    ];
    assert_eq!(listed, expected);
    assert_eq!(fs::read(&elsewhere)?, b"never followed");
    assert_eq!(fs::read_dir(&directory)?.count(), expected.len());
    assert_guard_retained(&root.0);
    Ok(())
}

#[test]
fn inventory_reads_one_byte_past_the_bound_and_no_further() -> TestResult {
    let (_root, guard, directory) = admitted()?;
    let limit = MAX_SUBJECT_KEY_ARTIFACT_BYTES;
    for (file, length) in [("a", limit), ("b", limit + 1), ("c", limit + 2)] {
        write_private(&directory.join(file), &vec![0x5a; length])?;
    }
    let lengths: Vec<_> = guard
        .list_and_read_subject_key_artifacts()?
        .into_iter()
        .map(|entry| match entry.content {
            SubjectKeyArtifactContent::Regular { bytes, .. } => Some(bytes.len()),
            SubjectKeyArtifactContent::NonRegular => None,
        })
        .collect();
    assert_eq!(lengths, [Some(limit), Some(limit + 1), Some(limit + 1)]);
    Ok(())
}

#[test]
fn inventory_accepts_exactly_the_entry_bound_and_fails_closed_above_it() -> TestResult {
    let (_root, guard, directory) = admitted()?;
    for index in 0..MAX_SUBJECT_KEY_ARTIFACT_ENTRIES {
        write_private(&directory.join(format!("{index:05}")), b"")?;
    }
    let names = entry_names(&guard)?;
    assert_eq!(names.len(), MAX_SUBJECT_KEY_ARTIFACT_ENTRIES);
    assert_eq!(names.first().map(Vec::as_slice), Some(&b"00000"[..]));
    assert_eq!(names.last().map(Vec::as_slice), Some(&b"04095"[..]));
    private_directory(&directory.join("one-more"))?;
    assert_eq!(
        guard.list_and_read_subject_key_artifacts(),
        Err(UNAVAILABLE)
    );
    Ok(())
}
