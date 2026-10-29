#![cfg(any(test, feature = "test-support"))]
//! Private commit/recovery stage boundaries and process-crash witnesses.

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::super::{remove_opened_temporary, FILE_FLAGS};
use super::{CommitStage, SubjectEncryptorLock, LEDGER_NAME, TEMPORARY_NAME};
use crate::encryptor_lock_test_support::{write_private, Sandbox};
use crate::{BridgeError, UnavailableCode};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROOT_ENV: &str = "PIGLOROS_LEDGER_REPLACE_PROBE_DIRECTORY";
const STOP_ENV: &str = "PIGLOROS_LEDGER_REPLACE_PROBE_STOP";
const PROBE: &str = "encryptor_lock::linux::nonce_ledger::replace::tests::crash_probe";
const STAGES: [CommitStage; 5] = [
    CommitStage::Created,
    CommitStage::Written,
    CommitStage::FileSynced,
    CommitStage::Renamed,
    CommitStage::DirectorySynced,
];

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        drop(self.0.kill());
        drop(self.0.wait());
    }
}

fn image(counter: u64) -> TestResult<Vec<u8>> {
    use pos_crypto::subject_nonce_ledger::{SubjectNonceLedgerRowV1, SubjectNonceLedgerV1};
    Ok(SubjectNonceLedgerV1::new([SubjectNonceLedgerRowV1 {
        owner_id: "subject:00000000000000000000000000000001".to_owned(),
        epoch: 1,
        root_material_digest: [9; 32],
        store_file_id: [7, 11],
        data_next: counter,
        bootstrap_next: 3,
    }])?
    .as_bytes()
    .to_vec())
}

fn prepare() -> TestResult<(Sandbox, SubjectEncryptorLock)> {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    write_private(&root.0.join("pigloros").join(LEDGER_NAME), &image(12)?)?;
    Ok((root, guard))
}

#[test]
fn stage_order_precedes_success_and_each_interruption_preserves_a_complete_image() -> TestResult {
    let (root, guard) = prepare()?;
    let path = root.0.join("pigloros").join(LEDGER_NAME);
    let old = image(12)?;
    let candidate = image(13)?;
    let mut observed = Vec::new();
    guard.replace_observing(&candidate, |stage| {
        observed.push(stage);
        Ok(())
    })?;
    assert_eq!(observed, STAGES);
    for stop in STAGES {
        guard.replace_nonce_ledger_bytes(&old)?;
        let result = guard.replace_observing(&candidate, |stage| {
            if stage == stop {
                Err(io::ErrorKind::Other.into())
            } else {
                Ok(())
            }
        });
        assert_eq!(
            result,
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        let expected = if [CommitStage::Renamed, CommitStage::DirectorySynced].contains(&stop) {
            &candidate
        } else {
            &old
        };
        assert_eq!(fs::read(&path)?, *expected);
        assert!(!root.0.join("pigloros").join(TEMPORARY_NAME).exists());
        assert!(SubjectEncryptorLock::acquire(&root.0).is_err());
    }
    Ok(())
}

#[test]
fn substituted_ledger_or_temporary_names_are_not_committed_or_cleaned_as_owned() -> TestResult {
    for name in [LEDGER_NAME, TEMPORARY_NAME] {
        let (root, guard) = prepare()?;
        let leaf = root.0.join("pigloros");
        let target = leaf.join(name);
        let retained = leaf.join("retained");
        let result = guard.replace_observing(&image(13)?, |stage| {
            if stage == CommitStage::FileSynced {
                fs::rename(&target, &retained)?;
                write_private(&target, b"substituted")?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&target)?, b"substituted");
        assert_eq!(
            fs::read(&retained)?,
            if name == LEDGER_NAME {
                image(12)?
            } else {
                image(13)?
            }
        );
        assert!(SubjectEncryptorLock::acquire(&root.0).is_err());
        if name == TEMPORARY_NAME {
            assert_eq!(guard.read_nonce_ledger_bytes()?, image(12)?);
        }
    }
    Ok(())
}

// Opening succeeded, then a rename removed only the path, retaining nlink=1.
// This isolates the later statat ENOENT from the allowed initial absence.
#[test]
fn orphan_cleanup_propagates_a_name_lost_after_open() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let leaf = root.0.join("pigloros");
    let path = leaf.join(TEMPORARY_NAME);
    write_private(&path, b"retained orphan")?;
    let file = rustix::fs::openat(
        &guard.directory,
        TEMPORARY_NAME,
        FILE_FLAGS,
        rustix::fs::Mode::empty(),
    )?;
    let retained = leaf.join("retained");
    fs::rename(path, &retained)?;
    assert_eq!(
        remove_opened_temporary(&guard.directory, &file),
        Err(rustix::io::Errno::NOENT)
    );
    assert_eq!(fs::read(retained)?, b"retained orphan");
    assert!(SubjectEncryptorLock::acquire(&root.0).is_err());
    Ok(())
}

const fn label(stage: CommitStage) -> &'static str {
    match stage {
        CommitStage::Created => "created",
        CommitStage::Written => "written",
        CommitStage::FileSynced => "file-synced",
        CommitStage::Renamed => "renamed",
        CommitStage::DirectorySynced => "directory-synced",
    }
}

fn spawn(root: &Sandbox, stop: &str) -> TestResult<Process> {
    Ok(Process(
        Command::new(std::env::current_exe()?)
            .args(["--exact", PROBE, "--nocapture", "--test-threads=1"])
            .env(ROOT_ENV, &root.0)
            .env(STOP_ENV, stop)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    ))
}

fn wait_marker(process: &mut Process, root: &Sandbox, deadline: Instant) -> TestResult {
    loop {
        if root.0.join("checkpoint").is_file() {
            return Ok(());
        }
        if let Some(status) = process.0.try_wait()? {
            return Err(format!("commit probe exited before its checkpoint: {status}").into());
        }
        if Instant::now() >= deadline {
            return Err("commit checkpoint deadline exceeded".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_exit(process: &mut Process, deadline: Instant) -> TestResult<ExitStatus> {
    loop {
        if let Some(status) = process.0.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("commit probe exit deadline exceeded".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn process_crashes_before_and_after_rename_recover_without_a_partial_image() -> TestResult {
    for stop in STAGES {
        let (root, guard) = prepare()?;
        drop(guard);
        let mut process = spawn(&root, label(stop))?;
        wait_marker(
            &mut process,
            &root,
            Instant::now() + Duration::from_secs(30),
        )?;
        assert!(!root.0.join("acknowledged").exists());
        assert!(SubjectEncryptorLock::acquire(&root.0).is_err());
        process.0.kill()?;
        let status = process.0.wait()?;
        assert!(!status.success());
        let guard = SubjectEncryptorLock::acquire(&root.0)?;
        let expected = if [CommitStage::Renamed, CommitStage::DirectorySynced].contains(&stop) {
            13
        } else {
            12
        };
        assert_eq!(guard.read_nonce_ledger_bytes()?, image(expected)?);
        assert!(!root.0.join("pigloros").join(TEMPORARY_NAME).exists());
    }
    Ok(())
}

#[test]
fn probe_harness_bounds_waits_and_rejects_an_unknown_checkpoint() -> TestResult {
    let (root, guard) = prepare()?;
    drop(guard);
    let mut unknown = spawn(&root, "unknown")?;
    let error = wait_marker(
        &mut unknown,
        &root,
        Instant::now() + Duration::from_secs(30),
    );
    assert!(error
        .err()
        .ok_or("unknown checkpoint succeeded")?
        .to_string()
        .contains("exited before"));
    let mut paused = Process(Command::new("/bin/sleep").arg("60").spawn()?);
    assert_eq!(
        wait_marker(&mut paused, &root, Instant::now())
            .err()
            .map(|error| error.to_string()),
        Some("commit checkpoint deadline exceeded".to_owned())
    );
    assert_eq!(
        wait_exit(&mut paused, Instant::now())
            .err()
            .map(|error| error.to_string()),
        Some("commit probe exit deadline exceeded".to_owned())
    );
    drop(paused);
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    assert_eq!(guard.read_nonce_ledger_bytes()?, image(12)?);
    Ok(())
}

#[test]
fn resumed_probe_acknowledges_only_after_the_complete_commit() -> TestResult {
    let (root, guard) = prepare()?;
    drop(guard);
    let mut process = spawn(&root, "created")?;
    wait_marker(
        &mut process,
        &root,
        Instant::now() + Duration::from_secs(30),
    )?;
    assert!(!root.0.join("acknowledged").exists());
    process
        .0
        .stdin
        .as_mut()
        .ok_or("missing probe input")?
        .write_all(b"x")?;
    assert!(wait_exit(&mut process, Instant::now() + Duration::from_secs(30))?.success());
    assert_eq!(fs::read(root.0.join("acknowledged"))?, b"committed");
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    assert_eq!(guard.read_nonce_ledger_bytes()?, image(13)?);
    Ok(())
}

#[test]
fn crash_probe() -> TestResult {
    let Ok(stop) = std::env::var(STOP_ENV) else {
        return Ok(());
    };
    assert!(
        STAGES.iter().any(|stage| label(*stage) == stop),
        "unknown checkpoint"
    );
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).ok_or("missing probe directory")?);
    let guard = SubjectEncryptorLock::acquire(&root)?;
    guard.replace_observing(&image(13)?, |stage| {
        if label(stage) == stop {
            fs::write(root.join("checkpoint"), label(stage))?;
            io::stdin().read_exact(&mut [0])?;
        }
        Ok(())
    })?;
    fs::write(root.join("acknowledged"), b"committed")?;
    Ok(())
}
