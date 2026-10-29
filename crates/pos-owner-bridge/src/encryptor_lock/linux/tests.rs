//! Narrow policy/fault tests for kernel facts unavailable to unprivileged CI:
//! foreign ownership, NFS, replaced device identity and an invalid parent fd.
//! Real acquisition, contention and filesystem layout use the public process tests.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn environment_selection_is_absolute_and_empty_xdg_uses_home() -> TestResult {
    for xdg in [None, Some(OsString::new())] {
        assert_eq!(
            selected_base(xdg.clone(), Some("/home/example".into()))?,
            (PathBuf::from("/home/example"), true)
        );
        for home in [None, Some(OsString::new()), Some("relative".into())] {
            assert_eq!(selected_base(xdg.clone(), home), Err(Errno::INVAL));
        }
    }
    assert_eq!(
        selected_base(Some("/state".into()), None)?,
        (PathBuf::from("/state"), false)
    );
    assert_eq!(
        selected_base(Some("relative".into()), Some("/home/example".into())),
        Err(Errno::INVAL)
    );
    Ok(())
}

#[test]
fn metadata_requires_exact_kind_effective_owner_and_permission_bits() -> TestResult {
    let descriptor = fs::openat(CWD, "/", DIRECTORY_FLAGS, Mode::empty())?;
    let mut stat = fs::fstat(&descriptor)?;
    stat.st_uid = rustix::process::geteuid().as_raw();
    stat.st_mode = FileType::Directory.as_raw_mode() | 0o700;
    assert!(private_metadata(&stat, FileType::Directory, 0o700));
    assert!(!private_metadata(&stat, FileType::RegularFile, 0o700));
    for mode in [0, 0o600, 0o755, 0o1700, 0o2700, 0o4700] {
        stat.st_mode = FileType::Directory.as_raw_mode() | mode;
        assert!(!private_metadata(&stat, FileType::Directory, 0o700));
    }
    stat.st_mode = FileType::RegularFile.as_raw_mode() | 0o600;
    assert!(private_metadata(&stat, FileType::RegularFile, 0o600));
    stat.st_uid ^= 1;
    assert!(!private_metadata(&stat, FileType::RegularFile, 0o600));
    assert_eq!(enforce(true), Ok(()));
    assert_eq!(enforce(false), Err(Errno::ACCESS));
    Ok(())
}

#[test]
fn nfs_and_either_changed_identity_component_are_rejected() -> TestResult {
    let directory = fs::openat(CWD, "/", DIRECTORY_FLAGS, Mode::empty())?;
    let mut filesystem = fs::fstatfs(&directory)?;
    filesystem.f_type = fs::NFS_SUPER_MAGIC;
    assert!(!not_nfs(&filesystem));
    filesystem.f_type = 0;
    assert!(not_nfs(&filesystem));
    let expected = fs::fstat(&directory)?;
    assert!(same_file(&expected, &expected));
    let mut replaced = expected;
    replaced.st_dev ^= 1;
    assert!(!same_file(&expected, &replaced));
    replaced = expected;
    replaced.st_ino ^= 1;
    assert!(!same_file(&expected, &replaced));
    Ok(())
}

#[test]
fn component_creation_propagates_kernel_failure() -> TestResult {
    let file = fs::openat(
        CWD,
        "/dev/null",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    assert_eq!(component(&file, "pigloros").err(), Some(Errno::NOTDIR));
    Ok(())
}

#[test]
fn opened_base_descriptors_are_close_on_exec() -> TestResult {
    let descriptor = fs::openat(CWD, "/", DIRECTORY_FLAGS, Mode::empty())?;
    assert!(rustix::io::fcntl_getfd(&descriptor)?.contains(rustix::io::FdFlags::CLOEXEC));
    Ok(())
}
