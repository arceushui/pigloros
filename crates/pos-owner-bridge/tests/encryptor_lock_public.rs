//! E16 admission through the real public constructor, isolated per subprocess.
//! No test changes the test runner's environment or umask.
#![cfg(target_os = "linux")]

use std::fs::{self, DirBuilder, Permissions};
use std::io::{self, Write as _};
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pos_owner_bridge::encryptor_lock::SubjectEncryptorLock;
use pos_owner_bridge::{BridgeError, UnavailableCode};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LOCK: &str = "pigloros.subject-encryptor.v1.lock";
const CASE: &str = "PIGLOROS_ENCRYPTOR_LOCK_PROBE";
const MARKER: &str = "ENCRYPTOR_LOCK_PROBE_EXECUTED";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> TestResult<Self> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pigloros-encryptor-lock-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        private_directory(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

fn private_directory(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(0o700).create(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o700))
}

fn probe(case: &str) -> TestResult<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", "lock_probe", "--nocapture", "--test-threads=1"])
        .env(CASE, case)
        .env_remove("XDG_STATE_HOME")
        .env_remove("HOME");
    Ok(command)
}

fn run(mut command: Command) -> TestResult<Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("lock probe exceeded its subprocess deadline".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output()?;
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains(MARKER));
    Ok(output)
}

fn assert_lock_is_close_on_exec() -> TestResult {
    let mut found = 0;
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        if fs::read_link(entry.path())
            .ok()
            .is_some_and(|target| target.file_name() == Some(std::ffi::OsStr::new(LOCK)))
        {
            let info = fs::read_to_string(Path::new("/proc/self/fdinfo").join(entry.file_name()))?;
            let flags = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:"))
                .ok_or("missing descriptor flags")?;
            assert_ne!(
                u64::from_str_radix(flags.trim(), 8)?
                    & u64::from(rustix::fs::OFlags::CLOEXEC.bits()),
                0
            );
            found += 1;
        }
    }
    assert_eq!(found, 1);
    Ok(())
}

#[test]
fn lock_probe() -> TestResult {
    let Ok(case) = std::env::var(CASE) else {
        return Ok(());
    };
    match case.as_str() {
        "acquire" => {
            let guard = SubjectEncryptorLock::acquire()?;
            assert_lock_is_close_on_exec()?;
            assert!(!format!("{guard:?}").is_empty());
        }
        "denied" | "restrictive-umask" => {
            let previous = (case == "restrictive-umask")
                .then(|| rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777)));
            let acquired = SubjectEncryptorLock::acquire();
            if let Some(previous) = previous {
                // Preserve the lock file permission assertion and restore the
                // mask before the instrumented runtime writes its exit profile.
                rustix::process::umask(previous);
            }
            assert_eq!(
                acquired.err(),
                Some(BridgeError::Unavailable(
                    UnavailableCode::InterfaceUnavailable
                ))
            );
        }
        "contention" => {
            let guard = SubjectEncryptorLock::acquire()?;
            assert_eq!(
                SubjectEncryptorLock::acquire().err(),
                Some(BridgeError::Unavailable(
                    UnavailableCode::InterfaceUnavailable
                ))
            );
            let state = std::env::var_os("XDG_STATE_HOME").ok_or("missing probe state")?;
            let mut contender = probe("denied")?;
            contender.env("XDG_STATE_HOME", &state);
            run(contender)?;
            drop(guard);
            let mut successor = probe("acquire")?;
            successor.env("XDG_STATE_HOME", state);
            run(successor)?;
        }
        _ => return Err("unknown lock probe".into()),
    }
    writeln!(io::stdout(), "{MARKER}")?;
    Ok(())
}

#[test]
fn contention_is_nonblocking_across_descriptors_and_processes_and_drop_releases() -> TestResult {
    let root = Sandbox::new()?;
    let mut command = probe("contention")?;
    command.env("XDG_STATE_HOME", &root.0);
    run(command)?;
    let lock = root.0.join("pigloros").join(LOCK);
    let original = fs::metadata(&lock)?;
    let mut command = probe("acquire")?;
    command.env("XDG_STATE_HOME", &root.0);
    run(command)?;
    let retained = fs::metadata(&lock)?;
    assert_eq!(
        (original.dev(), original.ino()),
        (retained.dev(), retained.ino())
    );
    assert_eq!(retained.permissions().mode() & 0o7777, 0o600);
    assert_eq!(retained.nlink(), 1);
    Ok(())
}

#[test]
fn home_fallback_creates_private_components_for_absent_and_empty_xdg() -> TestResult {
    let root = Sandbox::new()?;
    for empty_xdg in [false, true] {
        let mut command = probe("acquire")?;
        command.env("HOME", &root.0);
        if empty_xdg {
            command.env("XDG_STATE_HOME", "");
        }
        run(command)?;
    }
    for path in [".local", ".local/state", ".local/state/pigloros"] {
        assert_eq!(
            fs::metadata(root.0.join(path))?.permissions().mode() & 0o7777,
            0o700
        );
    }
    assert!(root.0.join(".local/state/pigloros").join(LOCK).is_file());
    Ok(())
}

#[test]
fn invalid_environment_paths_fail_before_creating_state() -> TestResult {
    let root = Sandbox::new()?;
    let file = root.0.join("file");
    fs::write(&file, b"untouched")?;
    for xdg in [PathBuf::from("relative"), root.0.join("missing"), file] {
        let mut command = probe("denied")?;
        command.env("XDG_STATE_HOME", xdg).env("HOME", &root.0);
        run(command)?;
    }
    run(probe("denied")?)?;
    for home in ["", "relative"] {
        let mut command = probe("denied")?;
        command.env("XDG_STATE_HOME", "").env("HOME", home);
        run(command)?;
    }
    assert!(!root.0.join(".local").exists());
    assert!(!root.0.join("pigloros").exists());
    Ok(())
}

#[test]
fn trusted_base_symlinks_are_followed_but_appended_components_are_not() -> TestResult {
    let root = Sandbox::new()?;
    let trusted = root.0.join("trusted");
    private_directory(&trusted)?;
    let alias = root.0.join("alias");
    symlink(&trusted, &alias)?;
    let mut command = probe("acquire")?;
    command.env("XDG_STATE_HOME", alias);
    run(command)?;
    assert!(trusted.join("pigloros").join(LOCK).is_file());
    for component in ["pigloros", ".local", ".local/state"] {
        let home = root.0.join(component.replace(['.', '/'], "x"));
        private_directory(&home)?;
        let link = home.join(component);
        if component == ".local/state" {
            private_directory(&home.join(".local"))?;
        }
        symlink(&trusted, &link)?;
        let mut command = probe("denied")?;
        if component == "pigloros" {
            command.env("XDG_STATE_HOME", &home);
        } else {
            command.env("HOME", &home);
        }
        run(command)?;
        assert!(fs::symlink_metadata(link)?.file_type().is_symlink());
    }
    Ok(())
}

#[test]
fn unsafe_lock_nodes_and_modes_are_rejected_without_replacement() -> TestResult {
    for kind in ["symlink", "hardlink", "directory", "mode", "special-mode"] {
        let root = Sandbox::new()?;
        let leaf = root.0.join("pigloros");
        private_directory(&leaf)?;
        let lock = leaf.join(LOCK);
        let original = root.0.join("original");
        fs::write(&original, b"retained")?;
        fs::set_permissions(&original, Permissions::from_mode(0o600))?;
        match kind {
            "symlink" => symlink(&original, &lock)?,
            "hardlink" => fs::hard_link(&original, &lock)?,
            "directory" => private_directory(&lock)?,
            _ => {
                fs::write(&lock, b"retained lock")?;
                let mode = if kind == "mode" { 0o640 } else { 0o1600 };
                fs::set_permissions(&lock, Permissions::from_mode(mode))?;
            }
        }
        let before = fs::symlink_metadata(&lock)?;
        let mut command = probe("denied")?;
        command.env("XDG_STATE_HOME", &root.0);
        run(command)?;
        let after = fs::symlink_metadata(&lock)?;
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(before.mode(), after.mode());
        assert_eq!(fs::read(original)?, b"retained");
    }
    Ok(())
}

#[test]
fn unsafe_leaf_permissions_and_creation_umask_fail_closed() -> TestResult {
    let root = Sandbox::new()?;
    let leaf = root.0.join("pigloros");
    private_directory(&leaf)?;
    for mode in [0o755, 0o1700] {
        fs::set_permissions(&leaf, Permissions::from_mode(mode))?;
        let mut command = probe("denied")?;
        command.env("XDG_STATE_HOME", &root.0);
        run(command)?;
        assert!(!leaf.join(LOCK).exists());
    }
    fs::set_permissions(&leaf, Permissions::from_mode(0o700))?;
    let mut command = probe("restrictive-umask")?;
    command.env("XDG_STATE_HOME", &root.0);
    run(command)?;
    assert_eq!(fs::metadata(leaf.join(LOCK))?.mode() & 0o7777, 0);
    fs::set_permissions(leaf.join(LOCK), Permissions::from_mode(0o600))?;
    let mut command = probe("acquire")?;
    command.env("XDG_STATE_HOME", &root.0);
    run(command)?;
    Ok(())
}
