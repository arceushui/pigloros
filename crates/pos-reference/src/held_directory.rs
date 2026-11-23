//! Listing a held directory descriptor without reopening it by path.
//!
//! The provider's restart sweeps (ADR-069 R11 §5.3 and Amendment 1 §5.4)
//! visit their directories only through descriptors they already hold.

use std::ffi::CString;
use std::fs::File;
use std::io;

use rustix::fs::Dir;

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
