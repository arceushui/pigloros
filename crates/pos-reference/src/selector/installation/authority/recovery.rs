//! Loading and preserving an already-committed SIR1 recovery floor.

mod completion;
mod identity;

pub use completion::{
    PreviousRuntimeTerminationProof, ProviderTerminationAuthority, RecoveryPeerTerminationProof,
};
pub use identity::{AdmittedProviderRuntime, InstallationRecoverySnapshot, ProviderRuntimeSlot};

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

use ciborium::value::Value;

use super::update::ValidatedInstallationUpdate;
use super::InstalledSelectorAuthority;
use crate::evaluator_protocol::{
    array, decode_canonical_with_limit, encode, fixed_bytes, text, uint,
};
#[cfg(test)]
use crate::sandbox_provider_protocol::SelectorRevocationState;
use crate::sandbox_provider_protocol::{
    AuthenticatedRevocationAcknowledgement, RecoveryCancellationContext,
};
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
    snapshot: InstallationRecoverySnapshot,
    sir1_digest: [u8; 32],
    recovery_file: File,
    recovery_bytes: Vec<u8>,
}

impl PendingInstallationRecovery {
    /// Exact committed RCU1 for the later control-only replay.
    #[must_use]
    pub fn revocation_update_bytes(&self) -> &[u8] {
        self.update.revocation_update_bytes()
    }

    /// Exact committed SIR1 self-digest.
    #[must_use]
    pub const fn sir1_digest(&self) -> [u8; 32] {
        self.sir1_digest
    }

    /// Exact RCC1 reconstructed from the committed SIR1 and retained RCU1.
    ///
    /// # Errors
    /// Rejects an internally inconsistent retained recovery identity.
    pub fn cancellation_context(
        &self,
    ) -> Result<RecoveryCancellationContext, SelectorBoundaryError> {
        RecoveryCancellationContext::for_committed_recovery(
            self.sir1_digest,
            self.snapshot.previous_provider_digest()?,
            self.update.revocation_update_bytes(),
            self.snapshot.previous_live_attempt_ids().to_vec(),
            self.snapshot.required_cancelled_attempt_ids().to_vec(),
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
    }

    /// Authenticate exact recovery RCA1 using only the previous SIR1-bound runtime key.
    ///
    /// `elapsed_ms` is measured from immediately before recovery-peer connect and
    /// therefore covers connect, framing, EOF, and acknowledgement processing.
    ///
    /// # Errors
    /// Rejects a deadline over 100 ms, any changed RCC1/RCU1/RCA1 binding, or a
    /// runtime key not active under the retained previous authority.
    #[cfg(test)]
    pub(crate) fn authenticate_recovery_acknowledgement(
        &self,
        acknowledgement_bytes: &[u8],
        elapsed_ms: u64,
    ) -> Result<AuthenticatedRevocationAcknowledgement, SelectorBoundaryError> {
        if elapsed_ms > 100 {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let context = self.cancellation_context()?;
        let mut state = SelectorRevocationState::new(
            self.previous_authority.revocation().clone(),
            self.previous_authority.trust(),
            self.snapshot.runtime_key_id(),
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        state
            .begin_update(
                self.update.revocation_update_bytes(),
                self.previous_authority.trust(),
                context,
                0,
            )
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        state
            .acknowledge(acknowledgement_bytes, elapsed_ms)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
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

    pub(super) fn verify_acknowledgement(
        &self,
        acknowledgement: &AuthenticatedRevocationAcknowledgement,
    ) -> Result<(), SelectorBoundaryError> {
        let context = self.cancellation_context()?;
        if acknowledgement.matches_context(
            &context,
            self.update
                .revocation_update()
                .next_revocation
                .snapshot_digest(),
        ) {
            Ok(())
        } else {
            Err(SelectorBoundaryError::ArtifactInvalid)
        }
    }

    /// Complete restart/overdue recovery only with both root-owned proofs and exact RCA1.
    ///
    /// # Errors
    /// Rejects any cross-transaction proof, acknowledgement mismatch, changed
    /// recovery floor, or durable publication/removal failure.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the three opaque completion capabilities are single-use"
    )]
    pub fn complete_recovery(
        self,
        previous: PreviousRuntimeTerminationProof,
        acknowledgement: AuthenticatedRevocationAcknowledgement,
        recovery_peer: RecoveryPeerTerminationProof,
    ) -> Result<InstalledSelectorObjects, SelectorBoundaryError> {
        self.verify_recovery_floor()?;
        self.verify_previous_proof(&previous)?;
        self.verify_acknowledgement(&acknowledgement)?;
        self.verify_peer_proof(&previous, &acknowledgement, &recovery_peer)?;
        let owner = self
            .previous_authority
            .installed
            .root
            .metadata()
            .map_err(|_| SelectorBoundaryError::Io)?
            .uid();
        super::update::durability::publish_successor(
            &self.previous_authority.installed.root,
            owner,
            self.update.previous_manifest_bytes(),
            self.update.next_manifest_bytes(),
            &self.recovery_file,
            &self.recovery_bytes,
        )
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
            snapshot,
            sir1_digest,
        } = decode_recovery(&recovery_bytes)?;
        if self.manifest_bytes != previous_bytes && self.manifest_bytes != next_bytes {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let previous_manifest = super::super::InstallationManifest::from_cbor(&previous_bytes)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let previous_authority = self.authenticate_manifest(&previous_manifest)?;
        snapshot.validate_against(&previous_authority)?;
        let update = previous_authority.validate_recovery_update(
            &previous_manifest,
            previous_bytes,
            next_bytes,
            update_bytes,
        )?;
        let pending = PendingInstallationRecovery {
            previous_authority,
            update,
            snapshot,
            sir1_digest,
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
    snapshot: InstallationRecoverySnapshot,
    sir1_digest: [u8; 32],
}

fn decode_recovery(bytes: &[u8]) -> Result<RecoveryRecords, SelectorBoundaryError> {
    let document = decode_canonical_with_limit(bytes, 48 * 1024 * 1024)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let wrapper = array(&document, 2).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let fields = array(&wrapper[0], 9).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
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
        if length == 0 || length > MANIFEST_LIMIT {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
    }
    let snapshot =
        InstallationRecoverySnapshot::from_values(&fields[5], &fields[6], &fields[7], &fields[8])?;
    let sir1_digest =
        fixed_bytes(&wrapper[1]).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let unsigned = encode(&wrapper[0]).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SIR1.v1\0");
    hasher.update(&unsigned);
    if hasher.finalize().as_bytes() != &sir1_digest {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(RecoveryRecords {
        previous: previous.clone(),
        next: next.clone(),
        update: update.clone(),
        snapshot,
        sir1_digest,
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
    use ed25519_dalek::SigningKey;

    fn encoded_recovery(previous_length: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let unsigned = Value::Array(vec![
            Value::Text("SIR1".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Bytes(vec![1; previous_length]),
            Value::Bytes(vec![2; 9 * 1024 * 1024]),
            Value::Bytes(vec![3]),
            Value::Array(vec![
                Value::Text("provider".to_owned()),
                Value::Bytes(vec![4; 32]),
                Value::Bytes(vec![5; 32]),
                Value::Bytes(vec![6; 32]),
                Value::Array(vec![
                    Value::Text("runtime".to_owned()),
                    Value::Integer(3_u64.into()),
                    Value::Bytes(
                        SigningKey::from_bytes(&[45; 32])
                            .verifying_key()
                            .to_bytes()
                            .to_vec(),
                    ),
                    Value::Integer(1_u64.into()),
                ]),
                Value::Bytes(vec![7; 16]),
                Value::Bytes(vec![8; 16]),
                Value::Integer(100_u64.into()),
                Value::Integer(200_u64.into()),
            ]),
            Value::Array(vec![
                Value::Bytes(vec![9; 16]),
                Value::Bytes(vec![10; 16]),
                Value::Bytes(vec![11; 16]),
            ]),
            Value::Array(Vec::new()),
            Value::Array(Vec::new()),
        ]);
        let unsigned_bytes =
            crate::evaluator_protocol::encode_with_limit(&unsigned, 48 * 1024 * 1024)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.SIR1.v1\0");
        hasher.update(&unsigned_bytes);
        Ok(crate::evaluator_protocol::encode_with_limit(
            &Value::Array(vec![
                unsigned,
                Value::Bytes(hasher.finalize().as_bytes().to_vec()),
            ]),
            48 * 1024 * 1024,
        )?)
    }

    #[test]
    fn recovery_envelope_has_a_separate_limit_from_embedded_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for length in [9 * 1024 * 1024, 16 * 1024 * 1024 + 1] {
            let encoded = encoded_recovery(length)?;
            assert!(encoded.len() > 16 * 1024 * 1024);
            assert_eq!(
                decode_recovery(&encoded).is_ok(),
                length <= 16 * 1024 * 1024
            );
        }
        Ok(())
    }
}
