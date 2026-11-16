//! ADR-069 R11 §6 bind rules (invariants 5 to 8), as root in the isolated
//! container, where `/run` is a fresh root-owned tmpfs.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use rustix::fs::{mknodat, FileType, Mode, CWD};

use super::{bind_endpoints, ProviderEndpoint};
use crate::provider_runtime::tests::{in_isolated_root, TestResult};
use crate::provider_runtime::ProviderRuntimeError;

const RUNTIME: &str = "/run/pigloros";
const EXECUTE: &str = "/run/pigloros/provider-execute.sock";
const CONTROL: &str = "/run/pigloros/provider-control.sock";

fn set_mode(path: &str, mode: u32) -> TestResult {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// The device and inode of the node at `path`, not followed.
fn identity(path: &str) -> TestResult<(u64, u64)> {
    let metadata = fs::symlink_metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

/// A named way to create one kind of node at `EXECUTE`.
type NodeCreator = (&'static str, fn() -> TestResult);

fn bind(path: &str) -> Result<ProviderEndpoint, ProviderRuntimeError> {
    ProviderEndpoint::bind(Path::new(path))
}

/// Each kind of pre-existing node at `EXECUTE` keeps its identity, and no
/// listener is bound there (invariant 5).
fn refuses_every_existing_node() -> TestResult {
    let creators: [NodeCreator; 5] = [
        ("regular file", || Ok(fs::write(EXECUTE, b"")?)),
        ("symlink", || Ok(symlink("/nonexistent", EXECUTE)?)),
        ("socket", || {
            drop(UnixListener::bind(EXECUTE)?);
            Ok(())
        }),
        ("directory", || Ok(fs::create_dir(EXECUTE)?)),
        ("FIFO", || {
            Ok(mknodat(
                CWD,
                EXECUTE,
                FileType::Fifo,
                Mode::from_raw_mode(0o600),
                0,
            )?)
        }),
    ];
    for (kind, create) in creators {
        create()?;
        let before = identity(EXECUTE)?;
        assert_eq!(
            bind(EXECUTE).err(),
            Some(ProviderRuntimeError::UnsafeEndpoint),
            "{kind}"
        );
        assert_eq!(identity(EXECUTE)?, before, "{kind}");
        if fs::symlink_metadata(EXECUTE)?.is_dir() {
            fs::remove_dir(EXECUTE)?;
        } else {
            fs::remove_file(EXECUTE)?;
        }
    }
    Ok(())
}

/// A bound leaf is a UID 0 socket of mode `0600`, checked around every
/// accept.
fn binds_an_owner_only_leaf() -> TestResult {
    let endpoint = bind(EXECUTE)?;
    let leaf = fs::symlink_metadata(EXECUTE)?;
    assert!(leaf.file_type().is_socket());
    assert_eq!(leaf.uid(), 0);
    assert_eq!(leaf.mode() & 0o7777, 0o600);
    endpoint.verify()?;
    // Non-blocking: nothing is pending.
    assert!(endpoint.accept()?.is_none());
    let mut client = UnixStream::connect(EXECUTE)?;
    let accepted = endpoint.accept()?;
    assert!(accepted.is_some());
    drop(accepted);
    let mut unread = Vec::new();
    client.read_to_end(&mut unread)?;
    assert!(unread.is_empty());
    // A leaf whose mode changed fails the check before an accept.
    set_mode(EXECUTE, 0o644)?;
    assert_eq!(endpoint.verify(), Err(ProviderRuntimeError::UnsafeEndpoint));
    assert_eq!(
        endpoint.accept().err(),
        Some(ProviderRuntimeError::UnsafeEndpoint)
    );
    set_mode(EXECUTE, 0o600)?;
    endpoint.verify()?;
    // A parent that is no longer the directory at its path fails it too.
    fs::rename(RUNTIME, "/run/pigloros-moved")?;
    fs::create_dir(RUNTIME)?;
    assert_eq!(endpoint.verify(), Err(ProviderRuntimeError::UnsafeEndpoint));
    fs::remove_dir(RUNTIME)?;
    fs::rename("/run/pigloros-moved", RUNTIME)?;
    endpoint.verify()?;
    // Dropping the endpoint removes its own leaf.
    drop(endpoint);
    assert!(!Path::new(EXECUTE).exists());
    Ok(())
}

/// A directory with an ancestor that a user other than root owns.
struct ForeignOwned {
    /// The directory whose ancestor is foreign-owned.
    directory: std::path::PathBuf,
    /// The directory this test created and chowned, removed on drop, even
    /// when an assertion panics.
    created: Option<&'static Path>,
}

impl Drop for ForeignOwned {
    fn drop(&mut self) {
        if let Some(created) = self.created {
            drop(fs::remove_dir(created));
        }
    }
}

/// A new directory chowned to `nobody`, or, where the container cannot
/// chown, the read-only checkout when a non-root user owns it (as on hosted
/// runners). Without either the test fails, unless
/// `PIGLOROS_NO_FOREIGN_OWNER_DIRECTORY` declares the environment unable;
/// then there is no such directory.
fn foreign_owned_directory() -> TestResult<Option<ForeignOwned>> {
    let created = Path::new("/run/pigloros/foreign");
    fs::create_dir(created)?;
    set_mode("/run/pigloros/foreign", 0o755)?;
    if std::os::unix::fs::chown(created, Some(65_534), Some(65_534)).is_ok() {
        return Ok(Some(ForeignOwned {
            directory: created.join("nested"),
            created: Some(created),
        }));
    }
    fs::remove_dir(created)?;
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR"));
    let foreign = checkout
        .ancestors()
        .any(|directory| fs::metadata(directory).is_ok_and(|metadata| metadata.uid() != 0));
    assert!(
        foreign || std::env::var_os("PIGLOROS_NO_FOREIGN_OWNER_DIRECTORY").is_some(),
        "no directory owned by another user: chown is refused and root owns the checkout"
    );
    Ok(foreign.then(|| ForeignOwned {
        directory: checkout.to_path_buf(),
        created: None,
    }))
}

/// Every directory from `/` to the parent is opened beneath the one before
/// it and must be a UID 0 directory that neither group nor other can write.
fn refuses_unsafe_ancestors() -> TestResult {
    // A world-writable ancestor (`/tmp` is `1777`).
    assert_eq!(
        bind("/tmp/provider.sock").err(),
        Some(ProviderRuntimeError::UnsafeEndpoint)
    );
    // A group-writable ancestor between `/run/pigloros` and the parent.
    fs::create_dir_all("/run/pigloros/shared/nested")?;
    set_mode("/run/pigloros/shared", 0o775)?;
    set_mode("/run/pigloros/shared/nested", 0o755)?;
    assert_eq!(
        bind("/run/pigloros/shared/nested/provider.sock").err(),
        Some(ProviderRuntimeError::UnsafeEndpoint)
    );
    fs::remove_dir_all("/run/pigloros/shared")?;
    // A symlink on the way, even to a safe directory.
    fs::create_dir("/run/pigloros/real")?;
    set_mode("/run/pigloros/real", 0o755)?;
    symlink("/run/pigloros/real", "/run/pigloros/link")?;
    assert_eq!(
        bind("/run/pigloros/link/provider.sock").err(),
        Some(ProviderRuntimeError::UnsafeEndpoint)
    );
    assert!(!Path::new("/run/pigloros/real/provider.sock").exists());
    // `..` cannot leave the directory it is resolved beneath; `.` names the
    // directory itself.
    assert_eq!(
        bind("/run/pigloros/real/../provider.sock").err(),
        Some(ProviderRuntimeError::UnsafeEndpoint)
    );
    assert!(!Path::new("/run/pigloros/provider.sock").exists());
    let current = bind("/run/pigloros/real/./provider.sock")?;
    assert!(fs::symlink_metadata("/run/pigloros/real/provider.sock")?
        .file_type()
        .is_socket());
    drop(current);
    fs::remove_file("/run/pigloros/link")?;
    fs::remove_dir("/run/pigloros/real")?;
    // An ancestor owned by another user.
    if let Some(foreign) = foreign_owned_directory()? {
        assert_eq!(
            ProviderEndpoint::bind(&foreign.directory.join("provider.sock")).err(),
            Some(ProviderRuntimeError::UnsafeEndpoint)
        );
    }
    Ok(())
}

#[test]
fn endpoints_bind_only_fresh_owner_only_leaves_beneath_safe_directories() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::endpoint::tests::endpoints_bind_only_fresh_owner_only_leaves_beneath_safe_directories",
    )? {
        return Ok(());
    }
    // No parent directory.
    assert_eq!(
        bind(EXECUTE).err(),
        Some(ProviderRuntimeError::UnsafeEndpoint)
    );
    fs::create_dir(RUNTIME)?;
    set_mode(RUNTIME, 0o755)?;
    // M4: the provider state directory and anything under it (invariant 8).
    for reserved in [
        "/run/pigloros/sandbox",
        "/run/pigloros/sandbox/provider.sock",
    ] {
        assert_eq!(
            bind(reserved).err(),
            Some(ProviderRuntimeError::ReservedEndpoint)
        );
        assert!(!Path::new(reserved).exists());
    }
    // A group- or other-writable parent.
    set_mode(RUNTIME, 0o775)?;
    assert_eq!(
        bind(EXECUTE).err(),
        Some(ProviderRuntimeError::UnsafeEndpoint)
    );
    assert!(!Path::new(EXECUTE).exists());
    set_mode(RUNTIME, 0o755)?;
    refuses_unsafe_ancestors()?;
    refuses_every_existing_node()?;
    binds_an_owner_only_leaf()?;
    // A second-bind failure removes the first leaf only (invariant 6).
    fs::write(CONTROL, b"")?;
    let control = identity(CONTROL)?;
    assert_eq!(
        bind_endpoints(Path::new(EXECUTE), Path::new(CONTROL)).err(),
        Some(ProviderRuntimeError::UnsafeEndpoint)
    );
    assert!(!Path::new(EXECUTE).exists());
    assert_eq!(identity(CONTROL)?, control);
    fs::remove_file(CONTROL)?;
    let (execute, control) = bind_endpoints(Path::new(EXECUTE), Path::new(CONTROL))?;
    // Orderly shutdown removes only a leaf that kept its identity
    // (invariant 7): the replaced execute leaf survives.
    fs::remove_file(EXECUTE)?;
    let replacement = UnixListener::bind(EXECUTE)?;
    let replaced = identity(EXECUTE)?;
    drop((execute, control));
    assert_eq!(identity(EXECUTE)?, replaced);
    assert!(!Path::new(CONTROL).exists());
    drop(replacement);
    Ok(())
}
