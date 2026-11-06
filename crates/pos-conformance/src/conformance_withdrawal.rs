//! The CWD1 conformance withdrawal of ADR-062 Revision 8 section 5.3 (slice G3, #1238).
//!
//! A CWD1 record is the exact deterministic-CBOR array
//!
//! ```text
//! [ "CWD1", 1, withdrawn_report_digest, [claim_layer, ...], reason_code,
//!   [source_kind, source_digest] / null, epoch, signer_key_id, record_digest ]
//! ```
//!
//! `withdrawn_report_digest` is the CNR1 report digest (field 23) and `signer_key_id` the
//! 32-byte report-signing key id. A `Corrected` withdrawal names its CCR1 correction and a
//! `ConflictResolved` one its CCF1 conflict; every other reason names no source. A withdrawn
//! report stays readable and is flagged, never deleted (wiki `ADR-062_R8_Governance_Records`).

use crate::{
    ClaimLayerV1, ConformanceGovernanceErrorV1 as Error, ConformanceReportV1,
    ConformanceWithdrawalReasonV1, ConformanceWithdrawalSourceKindV1, GovernanceEncoder,
    GovernanceRecordV1,
};
use ciborium::value::Value;

/// Magic of the CWD1 conformance withdrawal record.
pub const CONFORMANCE_WITHDRAWAL_MAGIC_V1: &str = "CWD1";

/// The correction or conflict record a withdrawal follows from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformanceWithdrawalSourceV1 {
    pub kind: ConformanceWithdrawalSourceKindV1,
    /// The CCR1 or CCF1 record digest.
    pub record_digest: [u8; 32],
}

/// One CWD1 conformance withdrawal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceWithdrawalV1 {
    pub withdrawn_report_digest: [u8; 32],
    pub withdrawn_claim_layers: Vec<ClaimLayerV1>,
    pub reason: ConformanceWithdrawalReasonV1,
    pub source: Option<ConformanceWithdrawalSourceV1>,
    pub epoch: u64,
    pub signer_key_id: [u8; 32],
    pub record_digest: [u8; 32],
}

/// A withdrawn report, still readable, flagged with what was withdrawn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceWithdrawnReportV1 {
    /// The unchanged CNR1 report.
    pub report: ConformanceReportV1,
    pub withdrawn_claim_layers: Vec<ClaimLayerV1>,
    /// The CWD1 record digest.
    pub withdrawal_digest: [u8; 32],
}

impl ConformanceWithdrawalV1 {
    /// The record digest recomputed over fields 0 through 7.
    #[must_use]
    pub fn computed_record_digest(&self) -> [u8; 32] {
        crate::governance_record_digest(self)
    }

    /// Validate every field rule and the record digest.
    ///
    /// # Errors
    /// Returns the closed error of the first violation.
    pub fn validate(&self) -> Result<(), Error> {
        crate::governance_validate(self)
    }

    /// Encode the withdrawal as its canonical CWD1 bytes.
    ///
    /// # Errors
    /// Returns the validation error when the withdrawal is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, Error> {
        crate::governance_encode(self)
    }

    /// Decode and validate exact canonical CWD1 bytes.
    ///
    /// # Errors
    /// Returns the closed error for oversized, malformed, non-canonical or invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, Error> {
        crate::governance_decode(bytes)
    }

    /// Read the withdrawn report from its exact CNR1 bytes and flag it.
    ///
    /// # Errors
    /// Returns the validation error, `ReportUnreadable` for bytes that are not a valid CNR1
    /// report, or `ReportMismatch` for another report.
    pub fn flag(&self, report_cnr1: &[u8]) -> Result<ConformanceWithdrawnReportV1, Error> {
        self.validate()?;
        let report = ConformanceReportV1::from_canonical_cbor(report_cnr1)
            .map_err(|_| Error::ReportUnreadable)?;
        if report.report_digest == self.withdrawn_report_digest {
            Ok(ConformanceWithdrawnReportV1 {
                report,
                withdrawn_claim_layers: self.withdrawn_claim_layers.clone(),
                withdrawal_digest: self.record_digest,
            })
        } else {
            Err(Error::ReportMismatch)
        }
    }
}

impl GovernanceRecordV1 for ConformanceWithdrawalV1 {
    const MAGIC: &'static str = CONFORMANCE_WITHDRAWAL_MAGIC_V1;
    const DOMAIN: &'static [u8] = b"PiglorOS.ConformanceWithdrawal.v1";
    const BODY_FIELDS: u64 = 6;

    fn encode_body(&self, encoder: &mut GovernanceEncoder) {
        encoder.bytes(&self.withdrawn_report_digest);
        encoder.open_array(self.withdrawn_claim_layers.len());
        for layer in &self.withdrawn_claim_layers {
            encoder.uint(u64::from(layer.wire_code()));
        }
        encoder.uint(self.reason.wire_code());
        encoder.optional(self.source, |encoder, source| {
            encoder.open_array(2);
            encoder.uint(source.kind.wire_code());
            encoder.bytes(&source.record_digest);
        });
        encoder.uint(self.epoch);
        encoder.bytes(&self.signer_key_id);
    }

    fn decode_body(body: Vec<Value>, record_digest: [u8; 32]) -> Result<Self, Error> {
        let [report, layers, reason, source, epoch, signer] = crate::governance_fields::<6>(body)?;
        Ok(Self {
            withdrawn_report_digest: crate::governance_fixed(report)?,
            withdrawn_claim_layers: crate::governance_array(layers)?
                .iter()
                .map(|layer| crate::governance_code(layer, crate::governance_claim_layer))
                .collect::<Result<_, _>>()?,
            reason: crate::governance_code(&reason, ConformanceWithdrawalReasonV1::from_wire_code)?,
            source: crate::governance_optional(source, decode_source)?,
            epoch: crate::governance_uint(&epoch)?,
            signer_key_id: crate::governance_fixed(signer)?,
            record_digest,
        })
    }

    fn stored_record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    fn check(&self) -> Result<(), Error> {
        if self.withdrawn_claim_layers.is_empty() {
            return Err(Error::FieldOutOfBounds);
        }
        crate::governance_epoch(self.epoch)?;
        if !crate::strictly_ordered(&self.withdrawn_claim_layers) {
            return Err(Error::NonCanonicalOrder);
        }
        let expected = match self.reason {
            ConformanceWithdrawalReasonV1::Corrected => {
                Some(ConformanceWithdrawalSourceKindV1::Correction)
            }
            ConformanceWithdrawalReasonV1::ConflictResolved => {
                Some(ConformanceWithdrawalSourceKindV1::Conflict)
            }
            ConformanceWithdrawalReasonV1::KeyRevoked
            | ConformanceWithdrawalReasonV1::EvidenceInvalid
            | ConformanceWithdrawalReasonV1::SubmitterRequest => None,
        };
        if self.source.map(|source| source.kind) == expected {
            Ok(())
        } else {
            Err(Error::InvalidWithdrawalSource)
        }
    }
}

fn decode_source(value: Value) -> Result<ConformanceWithdrawalSourceV1, Error> {
    let [kind, digest] = crate::governance_fields::<2>(crate::governance_array(value)?)?;
    Ok(ConformanceWithdrawalSourceV1 {
        kind: crate::governance_code(&kind, ConformanceWithdrawalSourceKindV1::from_wire_code)?,
        record_digest: crate::governance_fixed(digest)?,
    })
}
