//! Private temporary directories shared by Linux encryptor filesystem tests.

use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

/// A private fixture directory with best-effort cleanup when dropped.
pub struct Sandbox(pub PathBuf);

impl Sandbox {
    /// Create a unique private directory for this test process.
    ///
    /// # Errors
    /// Fails if the clock precedes its epoch or creating or securing the
    /// directory fails.
    pub fn new() -> TestResult<Self> {
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

/// Create a new directory with owner-only permissions.
///
/// # Errors
/// Returns the filesystem error if creation or setting mode `0o700` fails.
pub fn private_directory(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(0o700).create(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o700))
}

/// Write fixture bytes and set exact owner-only file permissions.
///
/// # Errors
/// Returns the filesystem error if writing or setting mode `0o600` fails.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes).and_then(|()| fs::set_permissions(path, Permissions::from_mode(0o600)))
}
