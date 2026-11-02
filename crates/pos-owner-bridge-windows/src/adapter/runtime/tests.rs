#![cfg(windows)]
#![forbid(unsafe_code)]

use std::fs::{File, FileTimes};
use std::process::Command;
use std::time::{Duration, SystemTime};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    base: PathBuf,
    runtime: PathBuf,
    cache: PathBuf,
    files: Vec<RuntimeFile>,
}

impl Fixture {
    fn new() -> Result<Self, std::io::Error> {
        let base = std::env::temp_dir().join(format!("piglor-runtime-{}", std::process::id()));
        std::fs::create_dir(&base)?;
        let runtime = base.join("runtime");
        std::fs::create_dir(&runtime)?;
        let mut files = Vec::new();
        for name in PER_START.into_iter().chain(["resources.pak"]) {
            let path = runtime.join(name);
            std::fs::create_dir_all(path.parent().ok_or(std::io::ErrorKind::InvalidInput)?)?;
            std::fs::write(path, b"good")?;
            files.push(RuntimeFile {
                path: name,
                size: 4,
                sha256: Sha256::digest(b"good").into(),
            });
        }
        Ok(Self {
            cache: base.join("cache"),
            base,
            runtime,
            files,
        })
    }

    fn verify(&self) -> Result<PathBuf, ()> {
        verify_installation(&self.runtime, &self.cache, &self.files, &[7; 32])
    }

    fn marker(&self) -> PathBuf {
        self.cache.join(MARKER_NAME)
    }

    fn restore(&self, name: &str) -> Result<(), std::io::Error> {
        std::fs::write(self.runtime.join(name), b"good")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.base);
    }
}

fn deny_reads(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new().read(true).share_mode(0).open(path)
}

fn set_modified(path: &Path, time: SystemTime) -> Result<(), std::io::Error> {
    OpenOptions::new()
        .write(true)
        .open(path)?
        .set_times(FileTimes::new().set_modified(time))
}

impl crate::Native {
    pub(crate) fn verify_runtime_cache_fixture() -> TestResult {
        let f = Fixture::new()?;
        let verified = f.verify().map_err(|()| "initial runtime rejected")?;
        assert_eq!(verified, f.runtime.canonicalize()?);
        let proof = VerifiedRuntime { root: verified };
        assert_eq!(proof.root(), f.runtime.canonicalize()?);
        assert_eq!(
            proof.browser_identity(std::process::id()),
            Err(BridgeError::Unavailable(UnavailableCode::RuntimeIntegrity))
        );
        assert_eq!(
            proof.browser_identity(u32::MAX),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        // Exercise the process-path admission seam independently of the
        // install fixture. Production callers cannot construct this proof.
        let executable = std::env::current_exe()?.canonicalize()?;
        let process_root = VerifiedRuntime {
            root: executable
                .parent()
                .ok_or("fixture executable has no parent")?
                .to_owned(),
        };
        assert_eq!(
            process_root.browser_identity(std::process::id())?,
            crate::process_identity(std::process::id())?
        );
        assert!(f.marker().is_file());

        // An independent sharing denial proves a matching cache does not rehash
        // ordinary resources. Every critical binary still must be opened/read.
        let resource = f.runtime.join("resources.pak");
        let lease = deny_reads(&resource)?;
        assert!(f.verify().is_ok());
        for name in PER_START {
            let critical_lease = deny_reads(&f.runtime.join(name))?;
            assert!(f.verify().is_err());
            drop(critical_lease);
        }
        std::fs::write(f.marker(), b"malformed cache")?;
        assert!(f.verify().is_err());
        drop(lease);
        assert!(f.verify().is_ok());
        let canonical_marker = std::fs::read(f.marker())?;
        std::fs::write(f.marker(), [canonical_marker.as_slice(), &[0]].concat())?;
        assert!(f.verify().is_ok());
        assert_eq!(std::fs::read(f.marker())?, canonical_marker);

        // Changed metadata invalidates the cache and rechecks a noncritical file.
        std::fs::write(&resource, b"evil")?;
        set_modified(
            &resource,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        )?;
        assert!(f.verify().is_err());
        f.restore("resources.pak")?;
        assert!(f.verify().is_ok());

        // A critical binary is rehashed even if its size and timestamp match.
        for name in PER_START {
            let path = f.runtime.join(name);
            let original_time = std::fs::metadata(&path)?.modified()?;
            std::fs::write(&path, b"evil")?;
            set_modified(&path, original_time)?;
            assert!(f.verify().is_err());
            f.restore(name)?;
            assert!(f.verify().is_ok());
        }
        std::fs::write(&resource, b"different size")?;
        assert!(f.verify().is_err());
        f.restore("resources.pak")?;
        let extra = f.runtime.join("unexpected.dll");
        std::fs::write(&extra, b"extra")?;
        assert!(f.verify().is_err());
        std::fs::remove_file(extra)?;
        std::fs::rename(&resource, f.runtime.join("renamed.pak"))?;
        assert!(f.verify().is_err());
        std::fs::rename(f.runtime.join("renamed.pak"), &resource)?;
        std::fs::remove_file(&resource)?;
        assert!(f.verify().is_err());
        f.restore("resources.pak")?;
        assert!(f.verify().is_ok());

        let junction = f.runtime.join("alias");
        let output = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&f.cache)
            .output()?;
        assert!(output.status.success());
        assert!(f.verify().is_err());
        std::fs::remove_dir(junction)?;
        std::fs::remove_file(f.marker())?;
        std::fs::create_dir(f.marker())?;
        assert!(f.verify().is_err());
        std::fs::remove_dir(f.marker())?;
        assert!(f.verify().is_ok());
        assert!(verify_fixed_runtime(&f.runtime, &f.cache).is_err());
        assert!(verify_fixed_runtime(Path::new("relative"), &f.cache).is_err());
        Ok(())
    }
}
