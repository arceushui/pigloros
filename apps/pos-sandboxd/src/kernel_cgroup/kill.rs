//! Whole-subtree escalation through the retained cgroup directory.

use std::io::Write;

use super::{
    openat2, AttemptCgroupError, BoundAttemptCgroup, BoundCgroupPath, File, Mode, OFlags,
    RESOLVE_CHILD,
};

impl BoundAttemptCgroup {
    /// Request SIGKILL for all processes in this cgroup and its descendants.
    ///
    /// Checks the bound directory identity before opening `cgroup.kill` beneath
    /// its retained descriptor and writing exactly `1`. No process ID or
    /// caller-provided filesystem path is used. If the path changes after that
    /// check, the write still targets only the retained original cgroup.
    ///
    /// Success acknowledges the kernel command only. The caller must separately
    /// observe cgroup emptiness, verify unit absence, and reconcile all resources
    /// within the cleanup deadline before reporting successful cleanup.
    ///
    /// # Errors
    /// Rejects a changed or missing cgroup, unsafe control-file resolution, or
    /// failed write. A missing target requires independent deletion evidence;
    /// it is not silently accepted as a successful kill.
    pub fn kill_all(&self) -> Result<(), AttemptCgroupError> {
        self.kill_all_with(|control| control.write_all(b"1"))
    }

    fn kill_all_with(
        &self,
        write: impl FnOnce(&mut File) -> std::io::Result<()>,
    ) -> Result<(), AttemptCgroupError> {
        if let BoundCgroupPath::Missing { .. } = self.inspect_path_with_metadata(File::metadata)? {
            return Err(AttemptCgroupError::KillTargetMissing);
        }
        let mut control = openat2(
            &self.directory,
            "cgroup.kill",
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            RESOLVE_CHILD,
        )
        .map(File::from)
        .map_err(AttemptCgroupError::KillOpen)?;
        write(&mut control).map_err(AttemptCgroupError::KillWrite)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{error::Error, fs, os::unix::fs::symlink, path::PathBuf};

    use super::*;
    use crate::{CgroupRoot, TransientServiceUnitName};
    use zbus::zvariant::OwnedObjectPath;

    struct Fixture {
        _root: tempfile::TempDir,
        directory: PathBuf,
        bound: BoundAttemptCgroup,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let root = tempfile::tempdir()?;
            let directory = root.path().join("attempt");
            fs::create_dir(&directory)?;
            fs::write(directory.join("cgroup.events"), b"populated 1\n")?;
            fs::write(directory.join("cgroup.kill"), b"0")?;
            let bound = BoundAttemptCgroup::open(
                CgroupRoot::for_test(File::open(root.path())?),
                TransientServiceUnitName::from_attempt_id([9; 16])?,
                OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/attempt")?,
                "/attempt".to_owned(),
            )?;
            Ok(Self {
                _root: root,
                directory,
                bound,
            })
        }
    }

    #[test]
    fn kill_writes_exact_command_without_claiming_empty() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        fixture.bound.kill_all()?;
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"1");
        assert!(matches!(
            fixture.bound.observe_empty(),
            Err(AttemptCgroupError::StillPopulated)
        ));
        // Repeating the command remains a command, never fabricated emptiness.
        fixture.bound.kill_all()?;
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"1");
        fs::write(fixture.directory.join("cgroup.events"), b"populated 0\n")?;
        let empty = fixture.bound.observe_empty()?;
        assert_eq!(empty.control_group(), "/attempt");
        assert_eq!(
            empty.unit_name(),
            &TransientServiceUnitName::from_attempt_id([9; 16])?
        );
        Ok(())
    }

    #[test]
    fn replaced_path_cannot_kill_original_or_replacement() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let moved = fixture.directory.with_file_name("original");
        fs::rename(&fixture.directory, &moved)?;
        fs::create_dir(&fixture.directory)?;
        fs::write(fixture.directory.join("cgroup.kill"), b"0")?;
        assert!(matches!(
            fixture.bound.kill_all(),
            Err(AttemptCgroupError::PathReused)
        ));
        assert_eq!(fs::read(moved.join("cgroup.kill"))?, b"0");
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        Ok(())
    }

    #[test]
    fn missing_target_is_not_a_successful_command() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let moved = fixture.directory.with_file_name("original");
        fs::rename(&fixture.directory, &moved)?;
        assert!(matches!(
            fixture.bound.kill_all(),
            Err(AttemptCgroupError::KillTargetMissing)
        ));
        assert_eq!(fs::read(moved.join("cgroup.kill"))?, b"0");
        fs::remove_dir_all(moved)?;
        assert!(matches!(
            fixture.bound.kill_all(),
            Err(AttemptCgroupError::KillTargetMissing)
        ));
        Ok(())
    }

    #[test]
    fn unsafe_or_missing_control_file_never_follows_another_target() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let control = fixture.directory.join("cgroup.kill");
        fs::remove_file(&control)?;
        assert!(matches!(
            fixture.bound.kill_all(),
            Err(AttemptCgroupError::KillOpen(_))
        ));
        assert!(!control.exists());
        let outside = fixture.directory.with_file_name("unrelated-control");
        fs::write(&outside, b"0")?;
        symlink(&outside, &control)?;
        assert!(matches!(
            fixture.bound.kill_all(),
            Err(AttemptCgroupError::KillOpen(_))
        ));
        assert_eq!(fs::read(&outside)?, b"0");
        fs::remove_file(&control)?;
        fs::create_dir(&control)?;
        assert!(matches!(
            fixture.bound.kill_all(),
            Err(AttemptCgroupError::KillOpen(_))
        ));
        Ok(())
    }

    #[test]
    fn write_failure_is_reported_without_cleanup_evidence() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        // An isolated regular-file fixture cannot induce a kernfs write failure.
        // Inject that I/O boundary while retaining real identity and open checks.
        let error = fixture
            .bound
            .kill_all_with(|_| Err(std::io::Error::other("kernel rejected kill")));
        assert!(matches!(error, Err(AttemptCgroupError::KillWrite(_))));
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        Ok(())
    }

    #[test]
    fn rename_after_open_cannot_redirect_the_write() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new()?;
        let moved = fixture.directory.with_file_name("original");
        // Schedule the race at the I/O boundary; the actual write uses the FD
        // opened by production code beneath the original retained directory.
        fixture.bound.kill_all_with(|control| {
            fs::rename(&fixture.directory, &moved)?;
            fs::create_dir(&fixture.directory)?;
            fs::write(fixture.directory.join("cgroup.kill"), b"0")?;
            control.write_all(b"1")
        })?;
        assert_eq!(fs::read(moved.join("cgroup.kill"))?, b"1");
        assert_eq!(fs::read(fixture.directory.join("cgroup.kill"))?, b"0");
        assert!(matches!(
            fixture.bound.kill_all(),
            Err(AttemptCgroupError::PathReused)
        ));
        Ok(())
    }
}
