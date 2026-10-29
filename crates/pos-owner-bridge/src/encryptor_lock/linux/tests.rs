//! Narrow policy/fault tests for kernel facts unavailable to unprivileged CI:
//! foreign ownership, NFS, replaced device identity and an invalid parent fd.
//! Real acquisition, contention and filesystem layout use the public process tests.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
    assert_eq!(
        open_or_create_directory_component(&file, "pigloros").err(),
        Some(Errno::NOTDIR)
    );
    Ok(())
}
