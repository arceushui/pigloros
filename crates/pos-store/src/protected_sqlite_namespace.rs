//! Pre-open refusal for ADR-129's dedicated Linux namespace.
//!
//! Finding the reserved coordination entry denies an ordinary native open;
//! its absence does not qualify a connection or grant protected use. The
//! qualified constructor still needs the complete activation/handle inventory,
//! common admission, native triplet proof and managed retirement. In particular,
//! this metadata check is not an atomic installation or a native file witness.

use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use pos_core::CoreError;

pub(crate) const COORDINATION_DIRECTORY: &str = ".pigloros-store-namespace-v1";
const REFUSAL: &str = "ordinary SQLite open cannot use the protected namespace";

fn refused() -> CoreError {
    CoreError::Storage(REFUSAL.to_owned())
}

/// Refuse an ordinary URI-enabled `SQLite` filename in the reserved namespace.
///
/// URI path escapes/authorities follow the pinned `SQLite` filename parser;
/// query/fragment text is not a pathname. The `SQLite` parser remains responsible
/// for native query/VFS semantics. Empty and `:memory:` names name no disk file.
///
/// # Errors
/// Returns a closed storage refusal for a reserved/uncertain path, invalid URI
/// authority or an unresolvable filesystem view, before creating a connection.
pub fn refuse_reserved_filename(filename: &str) -> Result<(), CoreError> {
    check_native_filename(filename.as_bytes())
}

/// Check both filesystem creation and native interpretation of a database path.
///
/// The pinned bundled build enables URI filenames by default, even without an
/// explicit open flag. A literal provisioning file and the native URI target
/// must therefore both be outside the reserved namespace. Non-UTF-8 path bytes
/// are checked exactly, without a lossy conversion.
///
/// # Errors
/// Returns the same closed pre-open refusal for either reserved interpretation.
pub fn refuse_reserved_database_path(path: &Path) -> Result<(), CoreError> {
    refuse_reserved_path(path).and_then(|()| {
        let filename = path.as_os_str().as_bytes();
        if filename.starts_with(b"file:") {
            check_native_filename(filename)
        } else {
            Ok(())
        }
    })
}

fn check_native_filename(filename: &[u8]) -> Result<(), CoreError> {
    filename_path(filename).and_then(|path| {
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            Ok(())
        } else {
            refuse_reserved_path(&path)
        }
    })
}

/// Refuse an ordinary literal filesystem path in the reserved namespace.
///
/// This checks filesystem operations such as literal file creation. Native
/// database callers use [`refuse_reserved_database_path`] to check both path
/// interpretations. Marker metadata is denial-only and never creates authority.
///
/// # Errors
/// Refuses a reserved coordination entry (of any kind), an uncertain lookup or
/// an unresolvable alias. No private native connection is opened by this check.
pub fn refuse_reserved_path(path: &Path) -> Result<(), CoreError> {
    let absolute = if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        closed(std::env::current_dir()).map(|current| current.join(path))
    };
    absolute.and_then(|absolute| {
        check_ancestors(&absolute).and_then(|()| {
            resolved_ancestor(absolute).and_then(|resolved| check_ancestors(&resolved))
        })
    })
}

fn check_ancestors(path: &Path) -> Result<(), CoreError> {
    path.ancestors().try_for_each(|ancestor| {
        std::fs::symlink_metadata(ancestor.join(COORDINATION_DIRECTORY))
            .is_err_and(|error| {
                error.kind() == ErrorKind::NotFound || error.kind() == ErrorKind::NotADirectory
            })
            .then_some(())
            .ok_or_else(refused)
    })
}

fn closed<T>(result: std::io::Result<T>) -> Result<T, CoreError> {
    result.map_err(|_| refused())
}

fn resolved_ancestor(path: PathBuf) -> Result<PathBuf, CoreError> {
    resolved_ancestor_reading_links(path, |path| std::fs::read_link(path))
}

// Keep link-read failure injectable after a real successful metadata lookup;
// otherwise exercising that refusal would require a nondeterministic FS race.
fn resolved_ancestor_reading_links(
    mut path: PathBuf,
    mut read_link: impl FnMut(&Path) -> std::io::Result<PathBuf>,
) -> Result<PathBuf, CoreError> {
    // Resolve within a finite budget, including missing leaf names. Exhaustion
    // denies an unknown path before any native connection can be created.
    for _ in 0..64 {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let target = closed(read_link(&path))?;
                if target.is_absolute() {
                    path = target;
                } else {
                    path.pop();
                    path.push(target);
                }
            }
            Ok(_) => return closed(std::fs::canonicalize(path)),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                path.pop();
            }
            Err(_) => return Err(refused()),
        }
    }
    Err(refused())
}

fn filename_path(filename: &[u8]) -> Result<PathBuf, CoreError> {
    let Some(mut uri) = filename.strip_prefix(b"file:") else {
        return Ok(PathBuf::from(OsString::from_vec(filename.to_vec())));
    };
    if let Some(authority_and_path) = uri.strip_prefix(b"//") {
        let end = authority_and_path
            .iter()
            .position(|byte| *byte == b'/')
            .unwrap_or(authority_and_path.len());
        let authority = &authority_and_path[..end];
        if !authority.is_empty() && authority != b"localhost" {
            return Err(refused());
        }
        uri = &authority_and_path[end..];
    }
    let end = uri
        .iter()
        .position(|byte| *byte == b'?' || *byte == b'#')
        .unwrap_or(uri.len());
    let raw = &uri[..end];
    let mut decoded = Vec::with_capacity(raw.len());
    let mut position = 0;
    while position < raw.len() {
        let octet = if raw[position] == b'%' {
            raw.get(position + 1..position + 3).and_then(percent_octet)
        } else {
            None
        };
        if let Some(byte) = octet {
            if byte == 0 {
                break;
            }
            decoded.push(byte);
            position += 3;
        } else {
            decoded.push(raw[position]);
            position += 1;
        }
    }
    Ok(PathBuf::from(OsString::from_vec(decoded)))
}

fn percent_octet(digits: &[u8]) -> Option<u8> {
    let digits = std::str::from_utf8(digits).ok()?;
    // Integer parsing permits a leading plus; SQLite percent escapes do not.
    if digits.starts_with('+') {
        None
    } else {
        u8::from_str_radix(digits, 16).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_uri_path_is_byte_exact_before_filesystem_refusal() {
        for (filename, expected) in [
            (&b"plain?#%20\xff"[..], &b"plain?#%20\xff"[..]),
            (b"file:relative.db?mode=ro", b"relative.db"),
            (b"file:relative.db#fragment", b"relative.db"),
            (b"file:///absolute.db?mode=ro#fragment", b"/absolute.db"),
            (
                b"file://localhost/absolute.db#fragment?mode=ro",
                b"/absolute.db",
            ),
            (b"file://localhost", b""),
            (b"file://", b""),
            (b"file:", b""),
            (b"file:%3f%23%2f%Af%ff", b"?#/\xaf\xff"),
            (b"file:x%00ignored.db", b"x"),
            (b"file:%+1%G0%0G%", b"%+1%G0%0G%"),
            (b"file:%\xff\xfe", b"%\xff\xfe"),
            (b"file:%\xc3\xa9", b"%\xc3\xa9"),
        ] {
            assert_eq!(
                filename_path(filename)
                    .expect("valid filename fixture")
                    .as_os_str()
                    .as_bytes(),
                expected
            );
        }
        for filename in [b"file://foreign/db".as_slice(), b"file://foreign"] {
            assert!(matches!(filename_path(filename),
                Err(CoreError::Storage(message)) if message == REFUSAL));
        }
    }

    #[test]
    fn every_percent_octet_preserves_case_independent_native_bytes() {
        for byte in 0..=u8::MAX {
            for escape in [format!("%{byte:02x}"), format!("%{byte:02X}")] {
                let filename = format!("file:a{escape}z");
                let expected = if byte == 0 {
                    vec![b'a']
                } else {
                    vec![b'a', byte, b'z']
                };
                assert_eq!(
                    filename_path(filename.as_bytes())
                        .expect("percent-escape fixture")
                        .as_os_str()
                        .as_bytes(),
                    expected
                );
            }
        }
    }

    #[test]
    fn unmarked_dangling_links_resolve_without_qualifying_a_native_connection() {
        let directory = tempfile::tempdir().expect("temporary alias directory");
        for (name, target) in [
            ("absolute", directory.path().join("missing.db")),
            ("relative", PathBuf::from("missing.db")),
        ] {
            let alias = directory.path().join(name);
            std::os::unix::fs::symlink(target, &alias).expect("dangling alias fixture");
            refuse_reserved_path(&alias).expect("unmarked dangling alias remains ordinary");
        }
        assert!(!directory.path().join("missing.db").exists());
    }

    #[test]
    fn resolver_budget_includes_absolute_relative_and_missing_path_steps() {
        let directory = tempfile::tempdir().expect("temporary resolver directory");
        let canonical = std::fs::canonicalize(directory.path()).expect("canonical fixture root");
        for kind in ["absolute", "relative"] {
            let parent = directory.path().join(kind);
            std::fs::create_dir(&parent).expect("resolver case directory");
            let target = parent.join("target");
            std::fs::write(&target, b"ordinary file").expect("ordinary target fixture");
            for index in 0..64 {
                let name = if index == 63 {
                    "target".to_owned()
                } else {
                    format!("link{}", index + 1)
                };
                let next = if kind == "absolute" {
                    parent.join(name)
                } else {
                    PathBuf::from(name)
                };
                std::os::unix::fs::symlink(next, parent.join(format!("link{index}")))
                    .expect("bounded symlink-chain fixture");
            }
            assert_eq!(
                resolved_ancestor(parent.join("link1")).expect("63-link chain is within budget"),
                std::fs::canonicalize(&target).expect("canonical target fixture")
            );
            assert!(matches!(resolved_ancestor(parent.join("link0")),
                Err(CoreError::Storage(message)) if message == REFUSAL));
        }
        let mut missing = directory.path().to_path_buf();
        for _ in 0..63 {
            missing.push("missing");
        }
        assert_eq!(
            resolved_ancestor(missing.clone()).expect("63 missing components are within budget"),
            canonical
        );
        missing.push("missing");
        assert!(matches!(resolved_ancestor(missing),
            Err(CoreError::Storage(message)) if message == REFUSAL));
    }

    #[test]
    fn link_read_failure_after_observed_symlink_is_closed_without_retry() {
        let directory = tempfile::tempdir().expect("temporary link-read directory");
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink("unopened-target", &alias).expect("real symlink fixture");
        let attempts = std::cell::Cell::new(0);
        let result = resolved_ancestor_reading_links(alias.clone(), |path| {
            assert_eq!(path, alias);
            attempts.set(attempts.get() + 1);
            Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "injected link read refusal",
            ))
        });
        assert!(matches!(result,
            Err(CoreError::Storage(message)) if message == REFUSAL));
        assert_eq!(attempts.get(), 1);
        assert!(!directory.path().join("unopened-target").exists());
    }
}
