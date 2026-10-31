#![cfg(target_os = "linux")]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Public filesystem interlock vectors; no qualified native binding is created.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdout, Command, Stdio};
    use std::time::{Duration, Instant};

    use pos_core::CoreError;
    use pos_store::owner_store_admission::{OwnerStoreAdmissionV1, OwnerStoreOperationV1};
    use pos_store::owner_store_interlock::OwnerStoreFileInterlockV1;

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const NAMESPACE: &str = ".pigloros-store-namespace-v1";
    const MAIN: &str = "main.db";
    const CHILD_DIRECTORY: &str = "PIGLOR_INTERLOCK_TEST_CHILD_DIRECTORY";

    struct Fixture {
        directory: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            create(directory.path(), MAIN)?;
            Ok(Self { directory })
        }

        fn path(&self) -> &Path {
            self.directory.path()
        }

        fn coordination(&self) -> PathBuf {
            self.path().join(NAMESPACE)
        }

        fn lock_path(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
            let metadata = fs::metadata(self.path().join(MAIN))?;
            Ok(self.coordination().join(format!(
                "store-namespace.v1.{:016x}.{:016x}.lock",
                metadata.dev(),
                metadata.ino()
            )))
        }
    }

    fn create(directory: &Path, name: &str) -> TestResult {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(name))?
            .write_all(b"unchanged file contents")?;
        Ok(())
    }

    fn refused<T>(result: Result<T, CoreError>) {
        let Err(error) = result else {
            std::panic::resume_unwind(Box::new("expected interlock refusal"));
        };
        assert_eq!(
            error.to_string(),
            CoreError::Storage("protected store interlock unavailable".to_owned()).to_string()
        );
    }

    fn enter(admission: &OwnerStoreAdmissionV1) -> OwnerStoreOperationV1<'_> {
        match admission.try_enter() {
            Ok(operation) => operation,
            Err(error) => std::panic::resume_unwind(Box::new(error)),
        }
    }

    #[test]
    fn contention_aliases_and_unrelated_directories_share_only_their_own_lock() -> TestResult {
        let fixture = Fixture::new()?;
        let other = Fixture::new()?;
        let aliases = tempfile::tempdir()?;
        symlink(fixture.path(), aliases.path().join("alias"))?;
        let admission = OwnerStoreAdmissionV1::new();
        let operation = enter(&admission);
        let held = OwnerStoreFileInterlockV1::try_acquire(&operation, fixture.path(), MAIN)?;
        assert_eq!(format!("{held:?}"), "OwnerStoreFileInterlockV1 { .. }");
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            fixture.path(),
            MAIN,
        ));
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            &aliases.path().join("alias"),
            MAIN,
        ));
        let unrelated = OwnerStoreFileInterlockV1::try_acquire(&operation, other.path(), MAIN)?;
        drop(unrelated);
        drop(held);
        let held = OwnerStoreFileInterlockV1::try_acquire(&operation, fixture.path(), MAIN)?;
        drop(held);
        operation.complete_cleanly();
        let lock = fixture.lock_path()?;
        assert_eq!(fs::metadata(&lock)?.permissions().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(lock)?.len(), 0);
        assert!(!fixture.path().join(format!("{MAIN}-wal")).exists());
        assert!(!fixture.path().join(format!("{MAIN}-shm")).exists());
        Ok(())
    }

    #[test]
    fn invalid_names_and_missing_or_unsafe_main_refuse_before_namespace_creation() -> TestResult {
        let fixture = Fixture::new()?;
        let admission = OwnerStoreAdmissionV1::new();
        let operation = enter(&admission);
        for name in [
            "",
            ".",
            "..",
            "/main",
            "sub/main",
            "main/",
            "file:main",
            NAMESPACE,
            "missing",
        ] {
            refused(OwnerStoreFileInterlockV1::try_acquire(
                &operation,
                fixture.path(),
                name,
            ));
        }
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            Path::new("relative"),
            MAIN,
        ));
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            &fixture.path().join("missing"),
            MAIN,
        ));
        fs::set_permissions(fixture.path().join(MAIN), fs::Permissions::from_mode(0o640))?;
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            fixture.path(),
            MAIN,
        ));
        assert!(!fixture.coordination().exists());
        operation.complete_cleanly();
        Ok(())
    }

    #[test]
    fn directories_symlinks_and_hard_links_cannot_be_main_candidates() -> TestResult {
        for kind in ["directory", "symlink", "hardlink"] {
            let fixture = Fixture::new()?;
            let original = fixture.path().join(MAIN);
            match kind {
                "directory" => {
                    fs::remove_file(&original)?;
                    fs::create_dir(&original)?;
                }
                "symlink" => {
                    fs::rename(&original, fixture.path().join("target"))?;
                    symlink("target", &original)?;
                }
                _ => fs::hard_link(&original, fixture.path().join("alias"))?,
            }
            let admission = OwnerStoreAdmissionV1::new();
            let operation = enter(&admission);
            refused(OwnerStoreFileInterlockV1::try_acquire(
                &operation,
                fixture.path(),
                MAIN,
            ));
            assert!(!fixture.coordination().exists());
            operation.complete_cleanly();
        }
        Ok(())
    }

    #[test]
    fn every_existing_companion_is_screened_before_any_coordination_creation() -> TestResult {
        for suffix in ["-wal", "-shm", "-journal"] {
            let fixture = Fixture::new()?;
            let name = format!("{MAIN}{suffix}");
            create(fixture.path(), &name)?;
            fs::set_permissions(
                fixture.path().join(&name),
                fs::Permissions::from_mode(0o640),
            )?;
            let admission = OwnerStoreAdmissionV1::new();
            let operation = enter(&admission);
            refused(OwnerStoreFileInterlockV1::try_acquire(
                &operation,
                fixture.path(),
                MAIN,
            ));
            assert!(!fixture.coordination().exists());
            assert_eq!(
                fs::read(fixture.path().join(name))?,
                b"unchanged file contents"
            );
            operation.complete_cleanly();
        }
        let fixture = Fixture::new()?;
        create(fixture.path(), &format!("{MAIN}-journal"))?;
        let admission = OwnerStoreAdmissionV1::new();
        let operation = enter(&admission);
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            fixture.path(),
            MAIN,
        ));
        assert!(!fixture.coordination().exists());
        operation.complete_cleanly();
        Ok(())
    }

    #[test]
    fn safe_existing_companions_keep_their_contents() -> TestResult {
        let fixture = Fixture::new()?;
        for suffix in ["-wal", "-shm"] {
            create(fixture.path(), &format!("{MAIN}{suffix}"))?;
        }
        let admission = OwnerStoreAdmissionV1::new();
        let operation = enter(&admission);
        let held = OwnerStoreFileInterlockV1::try_acquire(&operation, fixture.path(), MAIN)?;
        drop(held);
        for suffix in ["", "-wal", "-shm"] {
            assert_eq!(
                fs::read(fixture.path().join(format!("{MAIN}{suffix}")))?,
                b"unchanged file contents"
            );
        }
        operation.complete_cleanly();
        Ok(())
    }

    #[test]
    fn unsafe_database_or_coordination_directories_are_not_repaired() -> TestResult {
        let fixture = Fixture::new()?;
        let admission = OwnerStoreAdmissionV1::new();
        let operation = enter(&admission);
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o750))?;
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            fixture.path(),
            MAIN,
        ));
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))?;
        fs::create_dir(fixture.coordination())?;
        fs::set_permissions(fixture.coordination(), fs::Permissions::from_mode(0o750))?;
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            fixture.path(),
            MAIN,
        ));
        assert_eq!(
            fs::metadata(fixture.coordination())?.permissions().mode() & 0o7777,
            0o750
        );
        assert!(!fixture.lock_path()?.exists());
        operation.complete_cleanly();
        Ok(())
    }

    #[test]
    fn an_aliased_coordination_child_or_unsafe_lock_is_refused_without_repair() -> TestResult {
        let fixture = Fixture::new()?;
        let elsewhere = tempfile::tempdir()?;
        symlink(elsewhere.path(), fixture.coordination())?;
        let admission = OwnerStoreAdmissionV1::new();
        let operation = enter(&admission);
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            fixture.path(),
            MAIN,
        ));
        fs::remove_file(fixture.coordination())?;
        fs::create_dir(fixture.coordination())?;
        fs::set_permissions(fixture.coordination(), fs::Permissions::from_mode(0o700))?;
        let lock = fixture.lock_path()?;
        symlink(fixture.path().join(MAIN), &lock)?;
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            fixture.path(),
            MAIN,
        ));
        fs::remove_file(&lock)?;
        create(
            &fixture.coordination(),
            lock.file_name()
                .ok_or("missing name")?
                .to_str()
                .ok_or("non-UTF8 name")?,
        )?;
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o640))?;
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            fixture.path(),
            MAIN,
        ));
        assert_eq!(fs::metadata(&lock)?.permissions().mode() & 0o7777, 0o640);
        assert_eq!(fs::read(lock)?, b"unchanged file contents");
        operation.complete_cleanly();
        Ok(())
    }

    struct ChildPeer {
        child: Child,
        output: Option<ChildStdout>,
        pending: Vec<u8>,
    }

    impl ChildPeer {
        fn spawn(directory: &Path) -> Result<Self, Box<dyn std::error::Error>> {
            let child = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "tests::interlock_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_DIRECTORY, directory)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?;
            let mut peer = Self {
                child,
                output: None,
                pending: Vec::new(),
            };
            let output = peer.child.stdout.take().ok_or("missing child stdout")?;
            let flags = rustix::fs::fcntl_getfl(&output)?;
            rustix::fs::fcntl_setfl(&output, flags | rustix::fs::OFlags::NONBLOCK)?;
            peer.output = Some(output);
            Ok(peer)
        }

        fn command(&mut self, command: &[u8]) -> TestResult {
            self.child
                .stdin
                .as_mut()
                .ok_or("missing child stdin")?
                .write_all(command)?;
            Ok(())
        }

        fn await_marker(&mut self, marker: &str) -> TestResult {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut exited = false;
            loop {
                if Instant::now() >= deadline {
                    return Err("child marker deadline exceeded".into());
                }
                let mut bytes = [0; 1024];
                match self
                    .output
                    .as_mut()
                    .ok_or("missing child stdout")?
                    .read(&mut bytes)
                {
                    Ok(0) => return Err("child closed stdout before its marker".into()),
                    Ok(count) => {
                        self.pending.extend_from_slice(&bytes[..count]);
                        if self.pending.len() > 65_536 {
                            return Err("child output line exceeded fixture bound".into());
                        }
                        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                            let found = self.pending[..end].ends_with(marker.as_bytes());
                            let _removed = self.pending.drain(..=end).count();
                            if found {
                                return Ok(());
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if exited {
                            return Err("child exited before its marker".into());
                        }
                        exited = self.child.try_wait()?.is_some();
                        // Polling backoff only; readiness is proved by the pipe
                        // marker or child exit, never by elapsed sleep time.
                        if !exited {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }

        fn finish(&mut self, timeout: Duration) -> TestResult {
            let deadline = Instant::now() + timeout;
            loop {
                if let Some(status) = self.child.try_wait()? {
                    return status
                        .success()
                        .then_some(())
                        .ok_or_else(|| "child failed".into());
                }
                if Instant::now() >= deadline {
                    return Err("child termination deadline exceeded".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for ChildPeer {
        fn drop(&mut self) {
            // Child caches a reaped status; kill cannot target a reused PID.
            // On every error/unwind, terminate first and synchronously reap.
            let _kill_result = self.child.kill();
            let _wait_result = self.child.wait();
        }
    }

    #[test]
    fn a_separate_process_refuses_contention_then_acquires_after_release() -> TestResult {
        let fixture = Fixture::new()?;
        let admission = OwnerStoreAdmissionV1::new();
        let operation = enter(&admission);
        let held = OwnerStoreFileInterlockV1::try_acquire(&operation, fixture.path(), MAIN)?;
        let mut child = ChildPeer::spawn(fixture.path())?;
        child.await_marker("INTERLOCK_REFUSED")?;
        drop(held);
        operation.complete_cleanly();
        child.command(b"retry\n")?;
        child.await_marker("INTERLOCK_ACQUIRED")?;
        child.finish(Duration::from_secs(10))?;
        assert!(fixture.lock_path()?.is_file());
        Ok(())
    }

    #[test]
    fn child_owner_reaps_after_abandoned_wait_and_termination_timeout() -> TestResult {
        let fixture = Fixture::new()?;
        let admission = OwnerStoreAdmissionV1::new();
        let operation = enter(&admission);
        let held = OwnerStoreFileInterlockV1::try_acquire(&operation, fixture.path(), MAIN)?;
        for time_out in [false, true] {
            let mut child = ChildPeer::spawn(fixture.path())?;
            let pid = rustix::process::Pid::from_raw(i32::try_from(child.child.id())?)
                .ok_or("missing child PID")?;
            child.await_marker("INTERLOCK_REFUSED")?;
            if time_out {
                child.command(b"stall\n")?;
                child.await_marker("INTERLOCK_STALLED")?;
                assert!(child.finish(Duration::from_millis(20)).is_err());
            }
            drop(child);
            assert_eq!(
                rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).err(),
                Some(rustix::io::Errno::CHILD)
            );
        }
        drop(held);
        operation.complete_cleanly();
        Ok(())
    }

    #[test]
    fn interlock_child() -> TestResult {
        let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
            return Ok(());
        };
        let admission = OwnerStoreAdmissionV1::new();
        let operation = enter(&admission);
        refused(OwnerStoreFileInterlockV1::try_acquire(
            &operation,
            Path::new(&directory),
            MAIN,
        ));
        std::io::stdout().lock().write_all(b"INTERLOCK_REFUSED\n")?;
        let mut command = String::new();
        std::io::stdin().read_line(&mut command)?;
        if command == "stall\n" {
            std::io::stdout().lock().write_all(b"INTERLOCK_STALLED\n")?;
            command.clear();
            std::io::stdin().read_line(&mut command)?;
            return Err("stalled fixture unexpectedly resumed".into());
        }
        assert_eq!(command, "retry\n");
        let held = OwnerStoreFileInterlockV1::try_acquire(&operation, Path::new(&directory), MAIN)?;
        std::io::stdout()
            .lock()
            .write_all(b"INTERLOCK_ACQUIRED\n")?;
        drop(held);
        operation.complete_cleanly();
        Ok(())
    }
}
