//! Held provider directories, reached only through descriptors the caller
//! already holds and never reopened by path.
//!
//! The provider's restart sweeps (ADR-069 R11 §5.3 and Amendment 1 §5.4)
//! list their directories through those descriptors, and the capture store
//! root is opened or created beneath the held artifact root.

use std::ffi::CString;
use std::fs::File;
use std::io;

use rustix::fs::{fchmod, mkdirat, openat2, Dir, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// The mode of a directory this module creates.
const PRIVATE_MODE: Mode = Mode::RWXU;
/// A held directory's open flags (ADR-069 R11 Amendment 1 §5.4): read-only,
/// a directory only, close-on-exec and never through a final symlink.
const DIRECTORY_OPEN: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
/// Its resolution: beneath the parent, through no symlink, magic link or
/// mount crossing (§5.4, item P11). `NO_SYMLINKS` already implies
/// `NO_MAGICLINKS` and refuses a final symlink as `O_NOFOLLOW` does; §5.4
/// names all three, so all three are kept.
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

/// The names in the held `directory`, without `.` and `..`, in directory
/// order.
///
/// # Errors
/// Returns the I/O error when the descriptor is no directory or an entry
/// cannot be read.
pub fn entry_names(directory: &File) -> io::Result<Vec<CString>> {
    Dir::read_from(directory)
        .and_then(|entries| {
            entries
                .map(|entry| entry.map(|entry| entry.file_name().to_owned()))
                .collect::<Result<Vec<_>, _>>()
        })
        .map(|names| {
            names
                .into_iter()
                .filter(|name| name.to_bytes() != b"." && name.to_bytes() != b"..")
                .collect()
        })
        .map_err(io::Error::from)
}

/// Open the directory `name` beneath the held `parent`, creating it with
/// mode `0700` when absent.
///
/// It is resolved beneath `parent` without crossing a symlink, a magic link
/// or a mount, and opened with `O_NOFOLLOW`. A created directory is then set
/// to exactly `0700`, since the umask may have stripped bits. An existing one
/// is returned as it is: its owner and mode are the caller's to check.
///
/// # Errors
/// Returns the I/O error when it cannot be opened or created, including
/// through a link, a mount crossing or a non-directory.
pub fn open_or_create_beneath(parent: &File, name: &str) -> io::Result<File> {
    let open = || openat2(parent, name, DIRECTORY_OPEN, Mode::empty(), RESOLVE).map(File::from);
    open()
        .or_else(|error| {
            if error == Errno::NOENT {
                mkdirat(parent, name, PRIVATE_MODE)
                    .and_then(|()| open())
                    .and_then(|created| fchmod(&created, PRIVATE_MODE).map(|()| created))
            } else {
                Err(error)
            }
        })
        .map_err(io::Error::from)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use rustix::io::{fcntl_getfd, FdFlags};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn the_returned_directory_is_close_on_exec() -> TestResult {
        let parent = tempfile::tempdir()?;
        let held = File::open(parent.path())?;
        // Created, then reopened as it is.
        for _ in 0..2 {
            let opened = open_or_create_beneath(&held, "captures")?;
            assert!(fcntl_getfd(&opened)?.contains(FdFlags::CLOEXEC));
        }
        Ok(())
    }

    #[test]
    fn only_a_directory_is_opened() -> TestResult {
        let parent = tempfile::tempdir()?;
        fs::write(parent.path().join("captures"), b"")?;
        let held = File::open(parent.path())?;
        assert_eq!(
            open_or_create_beneath(&held, "captures")
                .map_err(|error| error.raw_os_error())
                .err(),
            Some(Some(Errno::NOTDIR.raw_os_error()))
        );
        assert!(parent.path().join("captures").is_file());
        Ok(())
    }

    #[test]
    fn nothing_outside_the_parent_is_opened_or_created() -> TestResult {
        let outside = tempfile::tempdir()?;
        let parent = outside.path().join("parent");
        fs::create_dir(&parent)?;
        let held = File::open(&parent)?;
        // An escape through `..` and an absolute name are refused before any
        // directory is created.
        let absolute = outside.path().join("absolute");
        for name in ["../escaped", absolute.to_str().ok_or("not UTF-8")?] {
            assert_eq!(
                open_or_create_beneath(&held, name)
                    .map_err(|error| error.raw_os_error())
                    .err(),
                Some(Some(Errno::XDEV.raw_os_error()))
            );
        }
        assert!(!outside.path().join("escaped").exists());
        assert!(!absolute.exists());
        Ok(())
    }

    #[test]
    fn no_symlink_is_followed() -> TestResult {
        let parent = tempfile::tempdir()?;
        let target = parent.path().join("target");
        fs::create_dir_all(target.join("inner"))?;
        symlink(&target, parent.path().join("link"))?;
        let held = File::open(parent.path())?;
        // A symlink as the last component, and one in an earlier component,
        // whose target directories both exist.
        assert!(open_or_create_beneath(&held, "link").is_err());
        assert_eq!(
            open_or_create_beneath(&held, "link/inner")
                .map_err(|error| error.raw_os_error())
                .err(),
            Some(Some(Errno::LOOP.raw_os_error()))
        );
        Ok(())
    }

    #[test]
    fn no_mount_is_crossed() -> TestResult {
        // `/proc` is always its own mount beneath `/`, and it exists, so
        // nothing is created. This needs a mounted procfs: without one the
        // open fails with another error and the test fails loudly, never
        // passing falsely.
        let held = File::open("/")?;
        assert_eq!(
            open_or_create_beneath(&held, "proc")
                .map_err(|error| error.raw_os_error())
                .err(),
            Some(Some(Errno::XDEV.raw_os_error()))
        );
        Ok(())
    }
}
