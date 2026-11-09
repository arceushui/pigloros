//! Ordinary `SQLite` entry points. Namespace refusal and the native/file effect
//! belong to one boundary so adapters cannot accidentally open before checking.
//! These factories do not qualify a protected connection or make installation
//! atomic; protected lifecycle ownership remains a separate obligation.

use pos_core::CoreError;
use rusqlite::{Connection, OpenFlags};

pub(crate) fn open_filename(filename: &str, flags: OpenFlags) -> Result<Connection, CoreError> {
    #[cfg(target_os = "linux")]
    crate::protected_sqlite_namespace::refuse_reserved_filename(filename)?;
    Connection::open_with_flags(filename, flags)
        .map_err(|error| CoreError::Storage(error.to_string()))
}

/// Preserve the adapter's distinction between namespace refusal and a failed
/// filesystem/native operation without exposing an unchecked path callback.
#[cfg(target_os = "linux")]
pub(crate) enum DatabasePathError<E> {
    NamespaceRefused,
    Operation(E),
}

#[cfg(target_os = "linux")]
pub(crate) fn open_database_path(
    path: &std::path::Path,
    flags: OpenFlags,
) -> Result<Connection, DatabasePathError<rusqlite::Error>> {
    crate::protected_sqlite_namespace::refuse_reserved_database_path(path)
        .map_err(|_| DatabasePathError::NamespaceRefused)?;
    Connection::open_with_flags(path, flags).map_err(DatabasePathError::Operation)
}

#[cfg(target_os = "linux")]
pub(crate) fn create_private_database_file(
    path: &std::path::Path,
) -> Result<(), DatabasePathError<std::io::Error>> {
    use std::os::unix::fs::OpenOptionsExt;

    crate::protected_sqlite_namespace::refuse_reserved_database_path(path)
        .map_err(|_| DatabasePathError::NamespaceRefused)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map(drop)
        .map_err(DatabasePathError::Operation)
}
