//! Authentication of the immutable SAU1 lifecycle audit chain.

use ciborium::value::Value;

use super::codec::{
    bounded_array, decode_document, digest32, id16, key_id, optional_digest, signed, uint,
    verify_digest, verify_signature,
};
use super::{SandboxProviderProtocolError, SandboxProviderReceipt, SandboxProviderResult};

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

    pub(super) fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        verify_signature("SAU1", &self.record_digest, &self.signature, key)
    }

    fn validate(&self, unsigned: &[Value; 8]) -> Result<(), SandboxProviderProtocolError> {
        let expected_authority_count = match self.event_code {
            0..=11 | 13 => 3,
            12 => 4,
            _ => return Err(SandboxProviderProtocolError::FieldOutOfBounds),
        };
        if self.authority_digests.len() != expected_authority_count
            || self.authority_digests.contains(&[0; 32])
            || (self.sequence == 0) != self.previous_digest.is_none()
            || self.previous_digest == Some([0; 32])
        {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        verify_digest("SAU1", unsigned, self.record_digest)
    }
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
    use super::*;
    use crate::sandbox_provider_protocol::ReceiptAuthority;

    #[test]
    fn audit_authority_rejects_an_unsupported_event_code() {
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
        let receipt = SandboxProviderReceipt {
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
            receipt_digest: [18; 32],
            signature: [0; 64],
        };

        assert!(!event_authority_matches(&record, &receipt));
    }
}
