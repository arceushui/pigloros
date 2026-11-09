use std::error::Error;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

// These tests run without `CAP_SYS_ADMIN`, as the workspace tests do; the
// privileged pinning tests live with the adapter's.

#[test]
fn a_namespace_that_cannot_be_unshared_fails_after_claiming_its_name() -> TestResult {
    let directory = tempfile::tempdir()?;
    let namespaces = NetworkNamespaces::pinned_under(directory.path());
    let name = NamespaceName::for_attempt([1; 16]);
    assert!(matches!(
        namespaces.create(&name),
        Err(NetlinkError::Io(Errno::PERM))
    ));
    assert!(directory.path().join(name.as_str()).is_file());
    // The name stays claimed until it is deleted.
    assert!(matches!(
        namespaces.create(&name),
        Err(NetlinkError::Io(Errno::EXIST))
    ));
    Ok(())
}

#[test]
fn missing_entries_open_as_none_and_delete_as_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let namespaces = NetworkNamespaces::pinned_under(directory.path().join("netns"));
    let name = NamespaceName::for_attempt([2; 16]);
    assert!(matches!(namespaces.open(&name), Ok(None)));
    assert!(namespaces.delete(&name).is_ok());
    // A directory that is a file holds no entries.
    let file = directory.path().join("file");
    std::fs::write(&file, b"")?;
    assert!(matches!(
        NetworkNamespaces::pinned_under(&file).open(&name),
        Err(NetlinkError::Io(Errno::NOTDIR))
    ));
    assert_eq!(
        NetworkNamespaces::system(),
        NetworkNamespaces::pinned_under("/run/netns")
    );
    Ok(())
}
