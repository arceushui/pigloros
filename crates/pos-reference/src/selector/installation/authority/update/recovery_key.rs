//! The recovery peer's runtime key, as the pending SIR1 names it (ADR-069
//! R12 §5.6).
//!
//! The recovery peer reads SIR1 from its fixed path under the SIC1 file
//! rules and verifies its self-digest. From it the peer takes only the
//! previous-provider binding's role-3 runtime key: its key ID and its public
//! key. The peer checks its SPI1 key file against that public key at
//! startup, and names that key ID in RCA1. Revocation does not apply: the
//! next RVS1 may revoke the key, and the recovery exchange is the
//! control-only exception.
//!
//! The peer does not rebuild SIR1. The selector does (R12 §4.1), and it
//! authenticates the peer's RCA1 under the key of the SIR1 it rebuilt.

use std::fs::File;

use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;

use super::durability::{read_bounded_immutable, sir1_self_digest, RECOVERY_LIMIT};
use super::map_protocol_to_artifact_invalid;
use crate::evaluator_protocol::{
    array, decode_canonical_with_limit, encode_with_limit, fixed_bytes, text, uint, ProtocolError,
};
use crate::selector::installation::{fixed_artifact_root, validate_directory, RECOVERY_NAME};
use crate::selector::SelectorBoundaryError;

/// The `trust-role` of a runtime-attestation key.
const RUNTIME_ATTESTATION_ROLE: u64 = 3;

/// The previous runtime's attestation key that the pending SIR1's
/// previous-provider binding names.
#[derive(Debug)]
pub struct PendingRecoveryRuntimeKey {
    key_id: String,
    public_key: VerifyingKey,
}

impl PendingRecoveryRuntimeKey {
    /// Reads the pending SIR1 of the fixed installation.
    ///
    /// # Errors
    /// `Io` or `ArtifactInvalid` for unsafe ancestry, no SIR1, a SIR1 file
    /// that breaks the SIC1 file rules or the 48 MiB bound, and a SIR1 whose
    /// envelope, self-digest, header or runtime key is malformed.
    pub fn read() -> Result<Self, SelectorBoundaryError> {
        fixed_artifact_root()
            .map_err(SelectorBoundaryError::from)
            .and_then(|root| Self::read_at(&root, 0))
    }

    fn read_at(root: &File, owner: u32) -> Result<Self, SelectorBoundaryError> {
        validate_directory(root, owner)
            .map_err(SelectorBoundaryError::from)
            .and_then(|()| {
                read_bounded_immutable(root, RECOVERY_NAME, owner, RECOVERY_LIMIT as u64)
            })
            .and_then(|bytes| Self::decode(&bytes).map_err(map_protocol_to_artifact_invalid))
    }

    /// The key of a canonical SIR1 envelope whose self-digest verifies.
    fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        decode_canonical_with_limit(bytes, RECOVERY_LIMIT).and_then(|document| {
            array(&document, 2).and_then(|envelope| {
                encode_with_limit(&envelope[0], RECOVERY_LIMIT)
                    .map(|unsigned| sir1_self_digest(&unsigned))
                    .and_then(|digest| {
                        fixed_bytes::<32>(&envelope[1])
                            .and_then(|recorded| {
                                (recorded == digest)
                                    .then_some(())
                                    .ok_or(ProtocolError::DigestMismatch)
                            })
                            .and_then(|()| Self::from_unsigned(&envelope[0]))
                    })
            })
        })
    }

    /// The runtime key of the previous-provider binding, field 5 of the nine
    /// unsigned SIR1 fields.
    fn from_unsigned(unsigned: &Value) -> Result<Self, ProtocolError> {
        array(unsigned, 9).and_then(|fields| {
            match (text(&fields[0]), uint(&fields[1])) {
                (Ok("SIR1"), Ok(1)) => array(&fields[5], 9),
                _ => Err(ProtocolError::InvalidEncoding),
            }
            .and_then(|binding| array(&binding[4], 4))
            .and_then(|key| {
                match (
                    text(&key[0]),
                    uint(&key[1]),
                    fixed_bytes::<32>(&key[2]),
                    uint(&key[3]),
                ) {
                    (Ok(key_id), Ok(RUNTIME_ATTESTATION_ROLE), Ok(public_key), Ok(_epoch)) => {
                        VerifyingKey::from_bytes(&public_key)
                            .ok()
                            .map(|public_key| Self {
                                key_id: key_id.to_owned(),
                                public_key,
                            })
                            .ok_or(ProtocolError::InvalidEncoding)
                    }
                    _ => Err(ProtocolError::InvalidEncoding),
                }
            })
        })
    }

    /// The runtime-attestation key ID, which RCA1 names.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The runtime-attestation public key, which the SPI1 key file must hold.
    #[must_use]
    pub const fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
