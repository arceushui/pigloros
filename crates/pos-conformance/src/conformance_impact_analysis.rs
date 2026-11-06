//! The CIA1 conformance impact analysis of ADR-062 Revision 8 section 5.3 (slice G3, #1238).
//!
//! A CIA1 record is the exact deterministic-CBOR array
//!
//! ```text
//! [ "CIA1", 1, correction_subject_digest, [[report_digest, effect], ...], record_digest ]
//! ```
//!
//! Entries are strictly ascending by report digest. `correction_subject_digest` is the CCR1
//! correction subject digest, and the CCR1 names this record by its record digest, so the two
//! records bind each other without a digest cycle (wiki `ADR-062_R8_Governance_Records`
//! section 5). Every report naming the corrected old digest must appear.

use crate::{
    ConformanceCorrectionV1, ConformanceGovernanceErrorV1 as Error, ConformanceImpactEffectV1,
    GovernanceEncoder, GovernanceRecordV1, MAX_CONFORMANCE_GOVERNANCE_LIST_ITEMS_V1,
};
use ciborium::value::Value;

/// Magic of the CIA1 conformance impact analysis record.
pub const CONFORMANCE_IMPACT_ANALYSIS_MAGIC_V1: &str = "CIA1";

/// One report a correction affects and the effect on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformanceAffectedReportV1 {
    pub report_digest: [u8; 32],
    pub effect: ConformanceImpactEffectV1,
}

/// One CIA1 conformance impact analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceImpactAnalysisV1 {
    pub correction_subject_digest: [u8; 32],
    pub affected_reports: Vec<ConformanceAffectedReportV1>,
    pub record_digest: [u8; 32],
}

impl ConformanceImpactAnalysisV1 {
    /// The record digest recomputed over fields 0 through 2.
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

    /// Encode the impact analysis as its canonical CIA1 bytes.
    ///
    /// # Errors
    /// Returns the validation error when the impact analysis is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, Error> {
        crate::governance_encode(self)
    }

    /// Decode and validate exact canonical CIA1 bytes.
    ///
    /// # Errors
    /// Returns the closed error for oversized, malformed, non-canonical or invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, Error> {
        crate::governance_decode(bytes)
    }

    /// Validate this impact analysis for `correction` and the digests of every published
    /// report naming the corrected old digest.
    ///
    /// # Errors
    /// Returns either record's validation error, `CorrectionMismatch` unless the two records
    /// bind each other, or `AffectedReportMissing` when a naming report has no entry.
    pub fn validate_for(
        &self,
        correction: &ConformanceCorrectionV1,
        reports_naming_old_digest: &[[u8; 32]],
    ) -> Result<(), Error> {
        self.validate()?;
        correction.validate()?;
        if self.correction_subject_digest != correction.correction_subject_digest()
            || correction.impact_analysis_digest != self.record_digest
        {
            return Err(Error::CorrectionMismatch);
        }
        if reports_naming_old_digest.iter().all(|digest| {
            self.affected_reports
                .binary_search_by(|entry| entry.report_digest.cmp(digest))
                .is_ok()
        }) {
            Ok(())
        } else {
            Err(Error::AffectedReportMissing)
        }
    }
}

impl GovernanceRecordV1 for ConformanceImpactAnalysisV1 {
    const MAGIC: &'static str = CONFORMANCE_IMPACT_ANALYSIS_MAGIC_V1;
    const DOMAIN: &'static [u8] = b"PiglorOS.ConformanceImpactAnalysis.v1";
    const BODY_FIELDS: u64 = 2;

    fn encode_body(&self, encoder: &mut GovernanceEncoder) {
        encoder.bytes(&self.correction_subject_digest);
        encoder.open_array(self.affected_reports.len());
        for entry in &self.affected_reports {
            encoder.open_array(2);
            encoder.bytes(&entry.report_digest);
            encoder.uint(entry.effect.wire_code());
        }
    }

    fn decode_body(body: Vec<Value>, record_digest: [u8; 32]) -> Result<Self, Error> {
        let [subject, affected] = crate::governance_fields::<2>(body)?;
        Ok(Self {
            correction_subject_digest: crate::governance_fixed(subject)?,
            affected_reports: crate::governance_array(affected)?
                .into_iter()
                .map(decode_affected_report)
                .collect::<Result<_, _>>()?,
            record_digest,
        })
    }

    fn stored_record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    fn check(&self) -> Result<(), Error> {
        if self.affected_reports.len() > MAX_CONFORMANCE_GOVERNANCE_LIST_ITEMS_V1 {
            Err(Error::FieldOutOfBounds)
        } else if self
            .affected_reports
            .windows(2)
            .all(|pair| pair[0].report_digest < pair[1].report_digest)
        {
            Ok(())
        } else {
            Err(Error::NonCanonicalOrder)
        }
    }
}

fn decode_affected_report(value: Value) -> Result<ConformanceAffectedReportV1, Error> {
    let [report, effect] = crate::governance_fields::<2>(crate::governance_array(value)?)?;
    Ok(ConformanceAffectedReportV1 {
        report_digest: crate::governance_fixed(report)?,
        effect: crate::governance_code(&effect, ConformanceImpactEffectV1::from_wire_code)?,
    })
}
