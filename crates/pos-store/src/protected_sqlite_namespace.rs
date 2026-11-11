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
    let mut raw = &uri[..end];
    let mut decoded = Vec::with_capacity(raw.len());
    // Consume at least one input byte on every iteration. Malformed escapes
    // stay literal, and output cannot grow beyond the original input length.
    while let Some((&literal, tail)) = raw.split_first() {
        raw = tail;
        let octet = if literal == b'%' {
            raw.get(..2).and_then(percent_octet)
        } else {
            None
        };
        if let Some(byte) = octet {
            if byte == 0 {
                break;
            }
            decoded.push(byte);
            raw = &raw[2..];
        } else {
            decoded.push(literal);
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

    type TestError = Box<dyn std::error::Error>;
    type TestResult = Result<(), TestError>;

    #[test]
    fn native_uri_path_is_byte_exact_before_filesystem_refusal() -> TestResult {
        [
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
        ]
        .into_iter()
        .try_for_each(|(filename, expected)| {
            filename_path(filename).map(|path| assert_eq!(path.as_os_str().as_bytes(), expected))
        })
        .map(|()| {
            for filename in [b"file://foreign/db".as_slice(), b"file://foreign"] {
                assert!(matches!(filename_path(filename),
                    Err(CoreError::Storage(message)) if message == REFUSAL));
            }
        })
        .map_err(TestError::from)
    }

    #[test]
    fn every_percent_octet_preserves_case_independent_native_bytes() -> TestResult {
        (0..=u8::MAX)
            .try_for_each(|byte| {
                [format!("%{byte:02x}"), format!("%{byte:02X}")]
                    .into_iter()
                    .try_for_each(|escape| {
                        let filename = format!("file:a{escape}z");
                        let expected = if byte == 0 {
                            vec![b'a']
                        } else {
                            vec![b'a', byte, b'z']
                        };
                        filename_path(filename.as_bytes())
                            .map(|path| assert_eq!(path.as_os_str().as_bytes(), expected))
                    })
            })
            .map_err(TestError::from)
    }

    #[test]
    fn unmarked_dangling_links_resolve_without_qualifying_a_native_connection() -> TestResult {
        tempfile::tempdir()
            .map_err(TestError::from)
            .and_then(|directory| {
                [
                    ("absolute", directory.path().join("missing.db")),
                    ("relative", PathBuf::from("missing.db")),
                ]
                .into_iter()
                .try_for_each(|(name, target)| -> TestResult {
                    let alias = directory.path().join(name);
                    std::os::unix::fs::symlink(target, &alias)
                        .map_err(TestError::from)
                        .and_then(|()| refuse_reserved_path(&alias).map_err(TestError::from))
                })
                .map(|()| assert!(!directory.path().join("missing.db").exists()))
            })
    }

    fn symlink_chain_fixture(parent: &Path, absolute: bool) -> std::io::Result<PathBuf> {
        let target = parent.join("target");
        std::fs::create_dir(parent)
            .and_then(|()| std::fs::write(&target, b"ordinary file"))
            .and_then(|()| {
                (0..64).try_for_each(|index| {
                    let name = if index == 63 {
                        "target".to_owned()
                    } else {
                        format!("link{}", index + 1)
                    };
                    let next = if absolute {
                        parent.join(name)
                    } else {
                        PathBuf::from(name)
                    };
                    std::os::unix::fs::symlink(next, parent.join(format!("link{index}")))
                })
            })
            .map(|()| target)
    }

    #[test]
    fn resolver_budget_includes_absolute_relative_and_missing_path_steps() -> TestResult {
        tempfile::tempdir().map_err(TestError::from).and_then(|directory| {
            std::fs::canonicalize(directory.path())
                .map_err(TestError::from)
                .and_then(|canonical| {
                    ["absolute", "relative"]
                        .into_iter()
                        .try_for_each(|kind| -> TestResult {
                            let parent = directory.path().join(kind);
                            symlink_chain_fixture(&parent, kind == "absolute")
                                .map_err(TestError::from)
                                .and_then(|target| {
                                    resolved_ancestor(parent.join("link1"))
                                        .map_err(TestError::from)
                                        .and_then(|resolved| {
                                            std::fs::canonicalize(target)
                                                .map_err(TestError::from)
                                                .map(|expected| {
                                                    assert_eq!(resolved, expected);
                                                    assert!(matches!(resolved_ancestor(parent.join("link0")),
                                                        Err(CoreError::Storage(message)) if message == REFUSAL));
                                                })
                                        })
                                })
                        })
                        .and_then(|()| {
                            let mut missing = directory.path().to_path_buf();
                            for _ in 0..63 {
                                missing.push("missing");
                            }
                            resolved_ancestor(missing.clone())
                                .map_err(TestError::from)
                                .map(|resolved| {
                                    assert_eq!(resolved, canonical);
                                    missing.push("missing");
                                    assert!(matches!(resolved_ancestor(missing),
                                        Err(CoreError::Storage(message)) if message == REFUSAL));
                                })
                        })
                })
        })
    }

    #[test]
    fn link_read_failure_after_observed_symlink_is_closed_without_retry() -> TestResult {
        tempfile::tempdir()
            .map_err(TestError::from)
            .and_then(|directory| {
                let alias = directory.path().join("alias");
                std::os::unix::fs::symlink("unopened-target", &alias)
                    .map_err(TestError::from)
                    .map(|()| {
                        let attempts = std::cell::Cell::new(0);
                        let result = resolved_ancestor_reading_links(alias.clone(), |path| {
                            assert_eq!(path, alias.as_path());
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
                    })
            })
    }
}
