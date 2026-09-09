//! Loading and preserving an already-committed SIR1 recovery floor.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

use ciborium::value::Value;

use super::update::ValidatedInstallationUpdate;
use super::InstalledSelectorAuthority;
use crate::evaluator_protocol::{array, decode_canonical_with_limit, text, uint};
use crate::selector::installation::{open_file, InstalledSelectorObjects, MANIFEST_LIMIT};
use crate::selector::SelectorBoundaryError;

const RECOVERY_NAME: &str = "installation-update.cbor";
const RECOVERY_LIMIT: u64 = 48 * 1024 * 1024;

/// A sealed, authenticated SIR1 transaction awaiting mandatory termination and replay.
///
/// This value grants only the later control-only recovery continuation. It
/// deliberately has no execution, admission, fresh-challenge, completion, or
/// reopening operation.
#[derive(Debug)]
pub struct PendingInstallationRecovery {
    previous_authority: InstalledSelectorAuthority,
    update: ValidatedInstallationUpdate,
    recovery_file: File,
    recovery_bytes: Vec<u8>,
}

impl PendingInstallationRecovery {
    /// Exact committed RCU1 for the later control-only replay.
    #[must_use]
    pub fn revocation_update_bytes(&self) -> &[u8] {
        self.update.revocation_update_bytes()
    }

    /// Verify that SIR1 and current SIC1 still form this retained recovery floor.
    ///
    /// # Errors
    /// Rejects replaced, unsafe, truncated, or altered SIR1 state, or a current
    /// SIC1 that is neither the exact retained prior nor successor manifest.
    pub fn verify_recovery_floor(&self) -> Result<(), SelectorBoundaryError> {
        let owner = self
            .previous_authority
            .installed
            .root
            .metadata()
            .map_err(|_| SelectorBoundaryError::Io)?
            .uid();
        let current = read_current_manifest(&self.previous_authority.installed.root, owner)?;
        if current != self.update.previous_manifest_bytes()
            && current != self.update.next_manifest_bytes()
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let on_disk = open_file(
            &self.previous_authority.installed.root,
            RECOVERY_NAME,
            owner,
            0o400,
            RECOVERY_LIMIT,
        )?;
        let on_disk_metadata = on_disk.metadata().map_err(|_| SelectorBoundaryError::Io)?;
        let retained_metadata = self
            .recovery_file
            .metadata()
            .map_err(|_| SelectorBoundaryError::Io)?;
        let length = u64::try_from(self.recovery_bytes.len())
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        if on_disk_metadata.dev() != retained_metadata.dev()
            || on_disk_metadata.ino() != retained_metadata.ino()
            || on_disk_metadata.len() != retained_metadata.len()
            || on_disk_metadata.len() != length
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        if read_file(&self.recovery_file, RECOVERY_LIMIT)? != self.recovery_bytes {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(())
    }
}

impl InstalledSelectorObjects {
    /// Load one committed SIR1 transaction without enabling normal startup.
    ///
    /// # Errors
    /// Rejects absent or unsafe recovery state, malformed or oversized SIR1,
    /// a current SIC1 outside the SIR1 old/next floor, invalid prior authority,
    /// invalid successor records, or a forged/mismatched RCU1.
    pub fn load_pending_recovery(
        self,
    ) -> Result<PendingInstallationRecovery, SelectorBoundaryError> {
        let owner = self
            .root
            .metadata()
            .map_err(|_| SelectorBoundaryError::Io)?
            .uid();
        let recovery_file = open_file(&self.root, RECOVERY_NAME, owner, 0o400, RECOVERY_LIMIT)?;
        let recovery_bytes = read_file(&recovery_file, RECOVERY_LIMIT)?;
        let RecoveryRecords {
            previous: previous_bytes,
            next: next_bytes,
            update: update_bytes,
        } = decode_recovery(&recovery_bytes)?;
        if self.manifest_bytes != previous_bytes && self.manifest_bytes != next_bytes {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let previous_manifest = super::super::InstallationManifest::from_cbor(&previous_bytes)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let previous_authority = self.authenticate_manifest(&previous_manifest)?;
        let update = previous_authority.validate_recovery_update(
            &previous_manifest,
            previous_bytes,
            next_bytes,
            update_bytes,
        )?;
        let pending = PendingInstallationRecovery {
            previous_authority,
            update,
            recovery_file,
            recovery_bytes,
        };
        pending.verify_recovery_floor()?;
        Ok(pending)
    }
}

struct RecoveryRecords {
    previous: Vec<u8>,
    next: Vec<u8>,
    update: Vec<u8>,
}

fn decode_recovery(bytes: &[u8]) -> Result<RecoveryRecords, SelectorBoundaryError> {
    let document = decode_canonical_with_limit(bytes, 48 * 1024 * 1024)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let fields = array(&document, 5).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    if text(&fields[0]).map_err(|_| SelectorBoundaryError::ArtifactInvalid)? != "SIR1"
        || uint(&fields[1]).map_err(|_| SelectorBoundaryError::ArtifactInvalid)? != 1
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let (Value::Bytes(previous), Value::Bytes(next), Value::Bytes(update)) =
        (&fields[2], &fields[3], &fields[4])
    else {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    };
    for record in [previous, next, update] {
        let length =
            u64::try_from(record.len()).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        if length > MANIFEST_LIMIT {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
    }
    Ok(RecoveryRecords {
        previous: previous.clone(),
        next: next.clone(),
        update: update.clone(),
    })
}

fn read_current_manifest(root: &File, owner: u32) -> Result<Vec<u8>, SelectorBoundaryError> {
    let manifest = open_file(root, "installation.cbor", owner, 0o400, MANIFEST_LIMIT)?;
    read_file(&manifest, MANIFEST_LIMIT)
}

fn read_file(file: &File, limit: u64) -> Result<Vec<u8>, SelectorBoundaryError> {
    let mut file = file.try_clone().map_err(|_| SelectorBoundaryError::Io)?;
    let metadata = file.metadata().map_err(|_| SelectorBoundaryError::Io)?;
    if metadata.len() > limit {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SelectorBoundaryError::Io)?;
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SelectorBoundaryError::Io)?;
    if bytes.len() != capacity {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn recovery_envelope_has_a_separate_limit_from_embedded_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for length in [9 * 1024 * 1024, 16 * 1024 * 1024 + 1] {
            let document = Value::Array(vec![
                Value::Text("SIR1".to_owned()),
                Value::Integer(1_u64.into()),
                Value::Bytes(vec![1; length]),
                Value::Bytes(vec![2; 9 * 1024 * 1024]),
                Value::Bytes(vec![3]),
            ]);
            let encoded =
                crate::evaluator_protocol::encode_with_limit(&document, 48 * 1024 * 1024)?;
            assert!(encoded.len() > 16 * 1024 * 1024);
            assert_eq!(
                decode_recovery(&encoded).is_ok(),
                length <= 16 * 1024 * 1024
            );
        }
        Ok(())
    }
}
