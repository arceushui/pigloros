//! The immutable SAU1 lifecycle audit chain: its encoder and its
//! authentication.

use ciborium::value::Value;

use super::codec::{
    bounded_array, bytes_value, decode_document, digest32, digest_list_value, encode, id16, key_id,
    optional_digest, optional_digest_value, record_digest, require_signature, signed, text_value,
    uint, uint_value, valid_key_id, verify_digest, verify_signature,
};
use super::{
    SandboxProviderProtocolError, SandboxProviderReceipt, SandboxProviderResult, Sau1,
    SelfDigested, Verified,
};

/// The signed body of one SAU1 event before its digest and signature exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxAuditRecordFields {
    /// Attempt whose lifecycle produced this event.
    pub attempt_id: [u8; 16],
    /// Zero-based position in the immutable chain.
    pub sequence: u64,
    /// Closed ADR-069 event code.
    pub event_code: u8,
    /// Event-specific authority digests.
    pub authority_digests: Vec<[u8; 32]>,
    /// Previous SAU1 digest, absent only at sequence zero.
    pub previous_digest: Option<[u8; 32]>,
    /// Provider runtime-attestation key ID.
    pub runtime_attestation_key_id: String,
}

/// One authenticated selector-consumed SAU1 event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxAuditRecord {
    /// Attempt whose lifecycle produced this event.
    pub attempt_id: [u8; 16],
    /// Zero-based position in the immutable chain.
    pub sequence: u64,
    /// Closed ADR-069 event code.
    pub event_code: u8,
    /// Event-specific authority digests.
    pub authority_digests: Vec<[u8; 32]>,
    /// Previous SAU1 digest, absent only at sequence zero.
    pub previous_digest: Option<[u8; 32]>,
    /// Selected provider runtime-attestation signer.
    pub runtime_attestation_key_id: String,
    /// Exact SAU1 self-digest.
    pub record_digest: [u8; 32],
    signature: [u8; 64],
}

impl SandboxAuditRecord {
    /// Validate the fields and self-digest them: the only input the
    /// runtime-attestation signer accepts for an SAU1 (ADR-069 R9 §5).
    ///
    /// # Errors
    /// Rejects an unknown event code, an authority-digest count other than
    /// the event's, a zero digest, a chain link inconsistent with the
    /// sequence, and an invalid key ID, as the decoder does.
    pub fn self_digested(
        fields: SandboxAuditRecordFields,
    ) -> Result<SelfDigested<Sau1>, SandboxProviderProtocolError> {
        validate_audit_fields(&fields)
            .and_then(|()| {
                record_digest(
                    "SAU1",
                    &Value::Array(audit_unsigned_value(&fields).to_vec()),
                )
            })
            .map(|digest| SelfDigested::sealed(fields, digest))
    }

    /// The signed record of a signature that verified under `key`, the
    /// admitted runtime-attestation key.
    ///
    /// # Errors
    /// `SignatureInvalid` when the signature verified under another key.
    pub fn new(
        verified: Verified<Sau1>,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self, SandboxProviderProtocolError> {
        if verified.key() == key {
            let (fields, record_digest, signature) = verified.into_parts();
            Ok(Self {
                attempt_id: fields.attempt_id,
                sequence: fields.sequence,
                event_code: fields.event_code,
                authority_digests: fields.authority_digests,
                previous_digest: fields.previous_digest,
                runtime_attestation_key_id: fields.runtime_attestation_key_id,
                record_digest,
                signature,
            })
        } else {
            Err(SandboxProviderProtocolError::SignatureInvalid)
        }
    }

    /// Exact canonical SAU1 bytes.
    ///
    /// # Errors
    /// Returns a closed error when the fields no longer match the
    /// self-digest, and an encoding error if they cannot be serialized.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxProviderProtocolError> {
        let unsigned = audit_unsigned_value(&self.fields());
        self.validate(&unsigned).and_then(|()| {
            encode(&Value::Array(vec![
                Value::Array(unsigned.to_vec()),
                bytes_value(&self.record_digest),
                bytes_value(&self.signature),
            ]))
        })
    }

    /// Decode and validate one exact canonical SAU1 record.
    ///
    /// # Errors
    /// Rejects malformed records, invalid event shapes, or incorrect self-digests.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let document = decode_document(bytes)?;
        let (fields, record_digest, signature) = signed::<8>(&document, "SAU1")?;
        let event_code = u8::try_from(uint(&fields[4])?)
            .map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)?;
        let authority_digests = bounded_array(&fields[5], 0)?
            .iter()
            .map(digest32)
            .collect::<Result<Vec<_>, _>>()?;
        let record = Self {
            attempt_id: id16(&fields[2])?,
            sequence: uint(&fields[3])?,
            event_code,
            authority_digests,
            previous_digest: optional_digest(&fields[6])?,
            runtime_attestation_key_id: key_id(&fields[7])?,
            record_digest,
            signature,
        };
        record.validate(fields).map(|()| record)
    }

    /// The runtime-attestation signature over the self-digest.
    #[must_use]
    pub const fn signature(&self) -> [u8; 64] {
        self.signature
    }

    pub(super) fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        verify_signature("SAU1", &self.record_digest, &self.signature, key)
    }

    fn fields(&self) -> SandboxAuditRecordFields {
        SandboxAuditRecordFields {
            attempt_id: self.attempt_id,
            sequence: self.sequence,
            event_code: self.event_code,
            authority_digests: self.authority_digests.clone(),
            previous_digest: self.previous_digest,
            runtime_attestation_key_id: self.runtime_attestation_key_id.clone(),
        }
    }

    fn validate(&self, unsigned: &[Value; 8]) -> Result<(), SandboxProviderProtocolError> {
        validate_audit_fields(&self.fields())?;
        require_signature(&self.signature)?;
        verify_digest("SAU1", unsigned, self.record_digest)
    }
}

/// The SAU1 event shapes: the authority-digest count of each closed event
/// code, nonzero digests and a link present exactly after sequence zero.
fn validate_audit_fields(
    fields: &SandboxAuditRecordFields,
) -> Result<(), SandboxProviderProtocolError> {
    let expected_authority_count = match fields.event_code {
        0..=11 | 13 => 3,
        12 => 4,
        _ => return Err(SandboxProviderProtocolError::FieldOutOfBounds),
    };
    if fields.attempt_id == [0; 16] || !valid_key_id(&fields.runtime_attestation_key_id) {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    if fields.authority_digests.len() != expected_authority_count
        || fields.authority_digests.contains(&[0; 32])
        || (fields.sequence == 0) != fields.previous_digest.is_none()
        || fields.previous_digest == Some([0; 32])
    {
        return Err(SandboxProviderProtocolError::InconsistentFields);
    }
    Ok(())
}

fn audit_unsigned_value(fields: &SandboxAuditRecordFields) -> [Value; 8] {
    [
        text_value("SAU1"),
        uint_value(1),
        bytes_value(&fields.attempt_id),
        uint_value(fields.sequence),
        uint_value(u64::from(fields.event_code)),
        digest_list_value(&fields.authority_digests),
        optional_digest_value(fields.previous_digest.as_ref()),
        text_value(&fields.runtime_attestation_key_id),
    ]
}

pub(super) fn authenticate_audit_chain(
    records: &[Vec<u8>],
    receipt: &SandboxProviderReceipt,
    result: &SandboxProviderResult,
    key: &ed25519_dalek::VerifyingKey,
) -> Result<Vec<SandboxAuditRecord>, SandboxProviderProtocolError> {
    if records.is_empty() || records.len() > 256 {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    let mut authenticated = Vec::with_capacity(records.len());
    for bytes in records {
        let record = SandboxAuditRecord::from_canonical_cbor(bytes)?;
        record.verify_signature(key)?;
        authenticated.push(record);
    }
    validate_chain(&authenticated, receipt, result)?;
    Ok(authenticated)
}

fn validate_chain(
    records: &[SandboxAuditRecord],
    receipt: &SandboxProviderReceipt,
    result: &SandboxProviderResult,
) -> Result<(), SandboxProviderProtocolError> {
    let events_match = records
        .iter()
        .map(|record| record.event_code)
        .eq(result.operational_events.iter().copied());
    let links_match = records.iter().enumerate().all(|(index, record)| {
        record.attempt_id == receipt.attempt_id
            && usize::try_from(record.sequence) == Ok(index)
            && record.runtime_attestation_key_id == receipt.runtime_attestation_key_id
            && record.previous_digest
                == index
                    .checked_sub(1)
                    .map(|previous| records[previous].record_digest)
    });
    let terminal_matches = records
        .last()
        .is_some_and(|record| record.record_digest == receipt.sau1_digest);
    let authority_matches = records
        .iter()
        .all(|record| event_authority_matches(record, receipt));
    if events_match && links_match && terminal_matches && authority_matches {
        Ok(())
    } else {
        Err(SandboxProviderProtocolError::InconsistentFields)
    }
}

fn event_authority_matches(record: &SandboxAuditRecord, receipt: &SandboxProviderReceipt) -> bool {
    let grant = receipt.authority.agr1_digest;
    let observed = receipt.kernel_observation_evidence;
    let expected = match record.event_code {
        0..=10 => Some(vec![
            grant,
            receipt.elm1_digest,
            receipt.termination_evidence,
        ]),
        11 => receipt
            .ready1_digest
            .map(|ready| vec![grant, ready, observed]),
        12 => receipt
            .ready1_digest
            .zip(receipt.release1_digest)
            .map(|(ready, release)| vec![grant, ready, release, observed]),
        13 => receipt
            .ready1_digest
            .filter(|_| receipt.release1_digest.is_none())
            .map(|ready| vec![grant, ready, observed]),
        _ => None,
    };
    expected.is_some_and(|expected| expected == record.authority_digests)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::sandbox_provider_protocol::{ReceiptAuthority, SandboxProviderReceiptFields};

    #[test]
    fn audit_authority_rejects_an_unsupported_event_code(
    ) -> Result<(), SandboxProviderProtocolError> {
        let record = SandboxAuditRecord {
            attempt_id: [1; 16],
            sequence: 0,
            event_code: 14,
            authority_digests: Vec::new(),
            previous_digest: None,
            runtime_attestation_key_id: "runtime-key".to_owned(),
            record_digest: [2; 32],
            signature: [0; 64],
        };
        let key = SigningKey::from_bytes(&[7; 32]);
        let unsigned = SandboxProviderReceipt::self_digested(SandboxProviderReceiptFields {
            attempt_id: [1; 16],
            authority: ReceiptAuthority {
                agr1_digest: [3; 32],
                spm1_digest: [4; 32],
                provider_binary_digest: [5; 32],
                lps1_digest: [6; 32],
                sim1_digest: [7; 32],
                apt1_digest: [8; 32],
                trs1_digest: [9; 32],
                rvs1_digest: [10; 32],
            },
            trust_epoch: 1,
            revocation_epoch: 1,
            policy_epoch: 1,
            hcp1_digest: [11; 32],
            elm1_digest: [12; 32],
            network_transcript_digests: Vec::new(),
            ready1_digest: None,
            release1_digest: None,
            requested_configuration_evidence: [13; 32],
            kernel_observation_evidence: [14; 32],
            negative_probe_evidence: [15; 32],
            termination_evidence: [16; 32],
            sau1_digest: [17; 32],
            runtime_attestation_key_id: "runtime-key".to_owned(),
        })?;
        let signature = key.sign(&unsigned.signature_message()).to_bytes();
        let public = key.verifying_key();
        let receipt = SandboxProviderReceipt::new(unsigned.verify(signature, &public)?, &public)?;

        assert!(!event_authority_matches(&record, &receipt));
        Ok(())
    }
}
