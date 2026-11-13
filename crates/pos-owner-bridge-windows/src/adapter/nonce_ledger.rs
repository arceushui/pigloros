#![cfg(windows)]
#![cfg(any(test, feature = "test-support"))]
#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};

use pos_owner_bridge::{BridgeError, UnavailableCode};

#[cfg(test)]
use crate::adapter::native_tests::{pass, pass_unwind};

#[cfg(test)]
pub(super) static NONCE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test-support access to the per-user named encryptor lock.
///
/// The explicit directory is test authority only; it does not affect the lock
/// name. Holding this guard neither opens a ledger nor authorizes encryption.
/// It is thread-bound and must remain held through quarantine and recovery.
#[must_use = "retain the lock for the owner lifetime"]
pub struct WindowsSubjectEncryptorLock {
    mutex: crate::SubjectMutex,
    pub(super) test_directory: PathBuf,
}

impl WindowsSubjectEncryptorLock {
    /// Acquire the OS-user-global lock without waiting.
    ///
    /// # Errors
    /// Refuses a non-absolute or unavailable test directory, contention,
    /// unsuitable object security, or any native failure without exposing paths
    /// or OS diagnostics.
    pub fn acquire(test_directory: &Path) -> Result<Self, BridgeError> {
        if !test_directory.is_absolute() || !test_directory.is_dir() {
            return Err(unavailable());
        }
        crate::SubjectMutex::acquire()
            .map(|mutex| Self {
                mutex,
                test_directory: test_directory.to_owned(),
            })
            .map_err(|()| unavailable())
    }
}

impl fmt::Debug for WindowsSubjectEncryptorLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsSubjectEncryptorLock")
            .field("mutex", &self.mutex)
            .finish_non_exhaustive()
    }
}

const fn unavailable() -> BridgeError {
    BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable)
}

/// Retires its probe process on every exit, so a failed assertion never
/// leaves a probe holding the lock or the fixture directory.
#[cfg(test)]
pub(super) struct Probe(pub(super) std::process::Child);

#[cfg(test)]
impl Drop for Probe {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _waited = self.0.wait();
    }
}

#[cfg(test)]
const CASE: &str = "PIGLOROS_WINDOWS_NONCE_LOCK_CASE";
#[cfg(test)]
const MARKER: &str = "WINDOWS_NONCE_LOCK_PROBE_EXECUTED";

#[cfg(test)]
impl crate::Native {
    pub(crate) fn exercise_native_lock() {
        let _serial = pass(NONCE_TEST_LOCK.lock());
        let directory = std::env::temp_dir();
        if let Ok(case) = std::env::var(CASE) {
            exercise_lock_probe_case(&case, &directory);
            return;
        }
        pass(crate::SubjectMutex::exercise_security_refusals());
        let foreign = pass(crate::SubjectMutex::create_wrong_acl_fixture());
        assert_eq!(
            WindowsSubjectEncryptorLock::acquire(&directory).err(),
            Some(unavailable())
        );
        drop(foreign);
        assert_eq!(
            WindowsSubjectEncryptorLock::acquire(Path::new("relative")).err(),
            Some(unavailable())
        );
        let guard = pass(WindowsSubjectEncryptorLock::acquire(&directory));
        assert_eq!(
            WindowsSubjectEncryptorLock::acquire(&directory).err(),
            Some(unavailable())
        );
        let other_directory = directory.clone();
        assert_eq!(
            pass_unwind(
                std::thread::spawn(
                    move || WindowsSubjectEncryptorLock::acquire(&other_directory).err()
                )
                .join()
            ),
            Some(unavailable())
        );
        run_lock_probe("denied");
        let retained = pass(crate::SubjectMutex::retain_second_handle());
        drop(guard);
        run_lock_probe("acquire");
        run_lock_probe("hold");
        run_lock_probe("acquire");
        drop(retained);

        exercise_abandonment(&directory);
    }
}

#[cfg(test)]
fn lock_probe_command(case: &str) -> std::process::Command {
    let mut command = std::process::Command::new(pass(std::env::current_exe()));
    command
        .args([
            "--exact",
            "tests::nonce_lock_native",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CASE, case)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
}

#[cfg(test)]
fn run_lock_probe(case: &str) {
    use std::io::Read as _;
    use std::time::{Duration, Instant};

    let mut probe = Probe(pass(
        lock_probe_command(case)
            .stdin(std::process::Stdio::null())
            .spawn(),
    ));
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = pass(probe.0.try_wait()) {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "nonce lock probe exceeded its deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut output = String::new();
    let mut diagnostics = String::new();
    pass(pass(probe.0.stdout.take().ok_or("missing probe stdout")).read_to_string(&mut output));
    pass(
        pass(probe.0.stderr.take().ok_or("missing probe stderr")).read_to_string(&mut diagnostics),
    );
    assert!(status.success(), "{status:?}: {output} {diagnostics}");
    assert_eq!(
        output.matches(MARKER).count(),
        if case == "hold" { 2 } else { 1 }
    );
}

#[cfg(test)]
fn exercise_lock_probe_case(case: &str, directory: &Path) {
    use std::io::{self, Write as _};

    if case == "denied" {
        assert_eq!(
            WindowsSubjectEncryptorLock::acquire(directory).err(),
            Some(unavailable())
        );
    } else {
        let hold = case == "hold";
        assert!(hold || case == "acquire", "unknown nonce lock probe");
        let guard = pass(WindowsSubjectEncryptorLock::acquire(directory));
        assert!(!format!("{guard:?}").is_empty());
        if hold {
            pass(writeln!(io::stdout(), "{MARKER}"));
            pass(io::stdout().flush());
            let mut line = String::new();
            assert_eq!(pass(io::stdin().read_line(&mut line)), 0);
        }
    }
    pass(writeln!(io::stdout(), "{MARKER}"));
}

#[cfg(test)]
fn exercise_abandonment(directory: &Path) {
    use std::io::{self, BufRead as _};
    use std::time::Duration;

    let mut probe = Probe(pass(
        lock_probe_command("hold")
            .stdin(std::process::Stdio::piped())
            .spawn(),
    ));
    let output = pass(probe.0.stdout.take().ok_or("missing probe stdout"));
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let ready = io::BufReader::new(output)
            .lines()
            .map_while(Result::ok)
            .any(|line| line.contains(MARKER));
        let _sent = sender.send(ready);
    });
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(30)),
        Ok(true),
        "abandoned lock probe failed to become ready"
    );
    let retained = pass(crate::SubjectMutex::retain_second_handle());
    drop(probe);
    pass_unwind(reader.join());
    let guard = pass(WindowsSubjectEncryptorLock::acquire(directory));
    assert!(guard.mutex.was_abandoned());
    drop(guard);
    drop(retained);
}
