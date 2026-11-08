//! Pre-open refusal for ADR-129's dedicated Linux namespace.
//!
//! Finding the reserved coordination entry denies an ordinary native open;
//! its absence does not qualify a connection or grant protected use. The
//! qualified constructor still needs the complete activation/handle inventory,
//! common admission, native triplet proof and managed retirement. In particular,
//! this metadata check is not an atomic installation or a native file witness.

use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStringExt;
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
/// This entry is for callers that do not enable URI interpretation. Marker
/// metadata is denial-only; caller-created markers never create authority.
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
            resolved_ancestor(absolute, 64).and_then(|resolved| check_ancestors(&resolved))
        })
    })
}

fn check_ancestors(path: &Path) -> Result<(), CoreError> {
    path.ancestors().try_for_each(|ancestor| {
        match std::fs::symlink_metadata(ancestor.join(COORDINATION_DIRECTORY)) {
            Ok(_) => Err(refused()),
            Err(error)
                if error.kind() == ErrorKind::NotFound
                    || error.kind() == ErrorKind::NotADirectory =>
            {
                Ok(())
            }
            Err(_) => Err(refused()),
        }
    })
}

fn closed<T>(result: std::io::Result<T>) -> Result<T, CoreError> {
    result.map_err(|_| refused())
}

fn resolved_ancestor(mut path: PathBuf, remaining: usize) -> Result<PathBuf, CoreError> {
    // Resolve within a finite budget, including missing leaf names. Exhaustion
    // denies an unknown path before any native connection can be created.
    if remaining == 0 {
        return Err(refused());
    }
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => closed(std::fs::read_link(&path))
            .and_then(|target| {
                if target.is_absolute() {
                    resolved_ancestor(target, remaining - 1)
                } else {
                    path.pop();
                    resolved_ancestor(path.join(target), remaining - 1)
                }
            }),
        Ok(_) => closed(std::fs::canonicalize(path)),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            path.pop();
            resolved_ancestor(path, remaining - 1)
        }
        Err(_) => Err(refused()),
    }
}

fn filename_path(filename: &str) -> Result<PathBuf, CoreError> {
    let Some(mut uri) = filename.strip_prefix("file:") else {
        return Ok(PathBuf::from(filename));
    };
    if let Some(authority_and_path) = uri.strip_prefix("//") {
        let end = authority_and_path
            .find('/')
            .unwrap_or(authority_and_path.len());
        let authority = &authority_and_path[..end];
        if !authority.is_empty() && authority != "localhost" {
            return Err(refused());
        }
        uri = &authority_and_path[end..];
    }
    let end = uri.find(['?', '#']).unwrap_or(uri.len());
    let raw = &uri.as_bytes()[..end];
    let mut decoded = Vec::with_capacity(raw.len());
    let mut position = 0;
    while position < raw.len() {
        let octet = if raw[position] == b'%' {
            raw.get(position + 1)
                .and_then(|first| hex(*first))
                .zip(raw.get(position + 2).and_then(|second| hex(*second)))
        } else {
            None
        };
        match octet {
            Some((first, second)) => {
                let byte = (first << 4) | second;
                if byte == 0 {
                    break;
                }
                decoded.push(byte);
                position += 3;
            }
            None => {
                decoded.push(raw[position]);
                position += 1;
            }
        }
    }
    Ok(PathBuf::from(OsString::from_vec(decoded)))
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
