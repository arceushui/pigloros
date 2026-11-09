#![cfg(windows)]
#![cfg(any(test, feature = "test-support"))]
#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;

use pos_owner_bridge::{BridgeError, UnavailableCode};

/// Test-support access to the per-user named encryptor lock.
///
/// The explicit directory is test authority only; it does not affect the lock
/// name. Holding this guard neither opens a ledger nor authorizes encryption.
/// It is thread-bound and must remain held through quarantine and recovery.
#[must_use = "retain the lock for the owner lifetime"]
pub struct WindowsSubjectEncryptorLock {
    _mutex: crate::ffi::SubjectMutex,
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
        crate::ffi::SubjectMutex::acquire()
            .map(|mutex| Self { _mutex: mutex })
            .map_err(|()| unavailable())
    }
}

impl fmt::Debug for WindowsSubjectEncryptorLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsSubjectEncryptorLock")
            .finish_non_exhaustive()
    }
}

const fn unavailable() -> BridgeError {
    BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable)
}

#[cfg(test)]
pub(crate) fn exercise_native_lock() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{self, BufRead as _, Write as _};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const CASE: &str = "PIGLOROS_WINDOWS_NONCE_LOCK_CASE";
    const MARKER: &str = "WINDOWS_NONCE_LOCK_PROBE_EXECUTED";
    let directory = std::env::temp_dir();
    if let Ok(case) = std::env::var(CASE) {
        match case.as_str() {
            "acquire" => {
                let guard = WindowsSubjectEncryptorLock::acquire(&directory)?;
                assert!(!format!("{guard:?}").is_empty());
            }
            "denied" => assert_eq!(
                WindowsSubjectEncryptorLock::acquire(&directory).err(),
                Some(unavailable())
            ),
            "hold" => {
                let _guard = WindowsSubjectEncryptorLock::acquire(&directory)?;
                writeln!(io::stdout(), "{MARKER}")?;
                io::stdout().flush()?;
                let mut line = String::new();
                io::stdin().read_line(&mut line)?;
            }
            _ => return Err("unknown nonce lock probe".into()),
        }
        writeln!(io::stdout(), "{MARKER}")?;
        return Ok(());
    }
    let probe = |case: &str| -> Result<(), Box<dyn std::error::Error>> {
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "tests::nonce_lock_native",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CASE, case)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                return Err("nonce lock probe exceeded its deadline".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output()?;
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains(MARKER));
        Ok(())
    };
    crate::ffi::SubjectMutex::exercise_security_refusals().map_err(|()| unavailable())?;
    let foreign =
        crate::ffi::SubjectMutex::create_wrong_acl_fixture().map_err(|()| unavailable())?;
    assert_eq!(
        WindowsSubjectEncryptorLock::acquire(&directory).err(),
        Some(unavailable())
    );
    drop(foreign);
    assert_eq!(
        WindowsSubjectEncryptorLock::acquire(Path::new("relative")).err(),
        Some(unavailable())
    );
    let guard = WindowsSubjectEncryptorLock::acquire(&directory)?;
    assert_eq!(
        WindowsSubjectEncryptorLock::acquire(&directory).err(),
        Some(unavailable())
    );
    let other_directory = directory.clone();
    assert_eq!(
        std::thread::spawn(move || WindowsSubjectEncryptorLock::acquire(&other_directory).err())
            .join()
            .map_err(|_| "nonce lock contender panicked")?,
        Some(unavailable())
    );
    probe("denied")?;
    let retained = crate::ffi::SubjectMutex::retain_second_handle().map_err(|()| unavailable())?;
    drop(guard);
    probe("acquire")?;
    drop(retained);

    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "tests::nonce_lock_native",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CASE, "hold")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let output = child.stdout.take().ok_or("missing child stdout")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = io::BufReader::new(output);
        let result = (|| -> io::Result<bool> {
            let mut line = String::new();
            loop {
                line.clear();
                if output.read_line(&mut line)? == 0 {
                    return Ok(false);
                }
                if line.contains(MARKER) {
                    return Ok(true);
                }
            }
        })();
        let _sent = sender.send(result);
    });
    let ready = receiver.recv_timeout(Duration::from_secs(30));
    if !matches!(ready, Ok(Ok(true))) {
        if child.try_wait()?.is_none() {
            child.kill()?;
        }
        child.wait()?;
        reader.join().map_err(|_| "nonce lock reader panicked")?;
        return Err("abandoned lock probe failed to become ready".into());
    }
    reader.join().map_err(|_| "nonce lock reader panicked")?;
    let retained = crate::ffi::SubjectMutex::retain_second_handle().map_err(|()| unavailable())?;
    child.kill()?;
    child.wait()?;
    let guard = WindowsSubjectEncryptorLock::acquire(&directory)?;
    assert!(guard._mutex.was_abandoned());
    drop(guard);
    drop(retained);
    Ok(())
}
