#![cfg(any(test, feature = "test-support"))]
//! Descriptor-derived candidate store metadata under the accepted Linux profile.

use rustix::fd::AsFd;
use rustix::fs::{self, FileType};

use super::{enforce, private_metadata};
use crate::{BridgeError, UnavailableCode};

/// Observe an open candidate file's Linux `[st_dev, st_ino]` pair for SNL1.
///
/// The descriptor must refer to a regular file owned by the effective UID with
/// permission bits exactly `0o600`. The existing SNL1 encoder adds platform tag
/// `1` to this pair. File contents and pathnames do not supply the identity;
/// aliases and duplicate descriptors of the same inode yield the same pair.
///
/// This borrows the caller's descriptor and observes metadata only. It proves
/// no SQLite/main-file provenance, WAL/shared-memory safety, canonical binding,
/// retained lease or nonce authority. The caller retains descriptor and
/// lifecycle ownership; this snapshot does not freeze metadata or prevent
/// pathname replacement. The remaining ADR-097/E15 activation gates apply.
///
/// # Errors
/// Returns `Unavailable(InterfaceUnavailable)` for an unsuitable file kind,
/// owner or mode, or any descriptor-metadata failure. No OS error escapes.
pub fn store_file_id(file: &impl AsFd) -> Result<[u64; 2], BridgeError> {
    fs::fstat(file)
        .and_then(|stat| {
            enforce(private_metadata(&stat, FileType::RegularFile, 0o600))
                .map(|()| [stat.st_dev, stat.st_ino])
        })
        .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
}
