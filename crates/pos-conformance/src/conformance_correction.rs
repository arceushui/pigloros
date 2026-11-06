//! The CCR1 conformance correction of ADR-062 Revision 8 section 5.3 (slice G3, #1238).
//!
//! A CCR1 record is the exact deterministic-CBOR array
//!
//! ```text
//! [ "CCR1", 1, corrected_artifact_kind, old_digest, replacement_digest,
//!   impact_analysis_digest, reason, [approver_id, ...], epoch, record_digest ]
//! ```
//!
//! A correction is a new record: the old digest stays published beside its replacement and
//! nothing is rewritten. `impact_analysis_digest` is the record digest of the CIA1 impact
//! analysis, which binds this correction through its correction subject digest (wiki
//! `ADR-062_R8_Governance_Records` section 5).

use crate::{
    ConformanceArtifactKindV1, ConformanceCorrectionReasonV1,
    ConformanceGovernanceErrorV1 as Error, GovernanceEncoder, GovernanceRecordV1,
};
use ciborium::value::Value;

/// Magic of the CCR1 conformance correction record.
pub const CONFORMANCE_CORRECTION_MAGIC_V1: &str = "CCR1";

const CORRECTION_SUBJECT_DOMAIN_V1: &[u8] = b"PiglorOS.ConformanceCorrectionSubject.v1";

/// One CCR1 conformance correction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceCorrectionV1 {
    pub corrected_artifact_kind: ConformanceArtifactKindV1,
    pub old_digest: [u8; 32],
    pub replacement_digest: [u8; 32],
    pub impact_analysis_digest: [u8; 32],
    pub reason: ConformanceCorrectionReasonV1,
    pub approver_ids: Vec<String>,
    pub epoch: u64,
    pub record_digest: [u8; 32],
}

impl ConformanceCorrectionV1 {
    /// The record digest recomputed over fields 0 through 8.
    #[must_use]
    pub fn computed_record_digest(&self) -> [u8; 32] {
        crate::governance_record_digest(self)
    }

    /// The correction subject digest a CIA1 impact analysis binds: BLAKE3 over
    /// `PiglorOS.ConformanceCorrectionSubject.v1`, one NUL byte and the canonical array
    /// `[corrected_artifact_kind, old_digest, replacement_digest]`.
    #[must_use]
    pub fn correction_subject_digest(&self) -> [u8; 32] {
        let mut encoder = GovernanceEncoder::array(3);
        encoder.uint(self.corrected_artifact_kind.wire_code());
        encoder.bytes(&self.old_digest);
        encoder.bytes(&self.replacement_digest);
        crate::domain_digest(CORRECTION_SUBJECT_DOMAIN_V1, &encoder.out)
    }

    /// Validate every field rule and the record digest.
    ///
    /// # Errors
    /// Returns the closed error of the first violation.
    pub fn validate(&self) -> Result<(), Error> {
        crate::governance_validate(self)
    }

    /// Encode the correction as its canonical CCR1 bytes.
    ///
    /// # Errors
    /// Returns the validation error when the correction is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, Error> {
        crate::governance_encode(self)
    }

    /// Decode and validate exact canonical CCR1 bytes.
    ///
    /// # Errors
    /// Returns the closed error for oversized, malformed, non-canonical or invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, Error> {
        crate::governance_decode(bytes)
    }
}

impl GovernanceRecordV1 for ConformanceCorrectionV1 {
    const MAGIC: &'static str = CONFORMANCE_CORRECTION_MAGIC_V1;
    const DOMAIN: &'static [u8] = b"PiglorOS.ConformanceCorrection.v1";
    const BODY_FIELDS: u64 = 7;

    fn encode_body(&self, encoder: &mut GovernanceEncoder) {
        encoder.uint(self.corrected_artifact_kind.wire_code());
        encoder.bytes(&self.old_digest);
        encoder.bytes(&self.replacement_digest);
        encoder.bytes(&self.impact_analysis_digest);
        encoder.uint(self.reason.wire_code());
        encoder.texts(&self.approver_ids);
        encoder.uint(self.epoch);
    }

    fn decode_body(body: Vec<Value>, record_digest: [u8; 32]) -> Result<Self, Error> {
        let [kind, old, replacement, impact, reason, approvers, epoch] =
            crate::governance_fields::<7>(body)?;
        Ok(Self {
            corrected_artifact_kind: crate::governance_code(
                &kind,
                ConformanceArtifactKindV1::from_wire_code,
            )?,
            old_digest: crate::governance_fixed(old)?,
            replacement_digest: crate::governance_fixed(replacement)?,
            impact_analysis_digest: crate::governance_fixed(impact)?,
            reason: crate::governance_code(&reason, ConformanceCorrectionReasonV1::from_wire_code)?,
            approver_ids: crate::governance_texts(approvers)?,
            epoch: crate::governance_uint(&epoch)?,
            record_digest,
        })
    }

    fn stored_record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    fn check(&self) -> Result<(), Error> {
        crate::governance_approvers(&self.approver_ids)?;
        crate::governance_epoch(self.epoch)?;
        if self.replacement_digest == self.old_digest {
            Err(Error::CorrectionWithoutChange)
        } else {
            Ok(())
        }
    }
}
