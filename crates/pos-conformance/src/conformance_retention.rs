//! The CRT1 conformance retention record of ADR-062 Revision 8 section 5.3 (slice G3, #1238).
//!
//! A CRT1 record is the exact deterministic-CBOR array
//!
//! ```text
//! [ "CRT1", 1, retired_artifact_digest, retired_artifact_kind, retirement_date,
//!   last_stable_major_at_retirement, earliest_removal_date, earliest_removal_stable_major,
//!   record_digest ]
//! ```
//!
//! Dates are UTC calendar dates `YYYY-MM-DD` (years 0001-9999). Both removal bounds are stored
//! and recomputed on decode: the date is the retirement date plus 24 calendar months, the day
//! clamped to the end of the month, and the major is the last Stable major plus two. Removal
//! before both bounds is refused (wiki `ADR-062_R8_Governance_Records` section 6). This is
//! the in-repo validator; release tooling enforces it at the first release (G5, #1240).

use crate::{
    ConformanceArtifactKindV1, ConformanceGovernanceErrorV1 as Error, GovernanceEncoder,
    GovernanceRecordV1,
};
use ciborium::value::Value;

/// Magic of the CRT1 conformance retention record.
pub const CONFORMANCE_RETENTION_MAGIC_V1: &str = "CRT1";
/// Calendar months a retired artifact stays available.
pub const CONFORMANCE_RETENTION_MONTHS_V1: u32 = 24;
/// Subsequent Stable majors a retired artifact stays available for.
pub const CONFORMANCE_RETENTION_STABLE_MAJORS_V1: u64 = 2;

/// One CRT1 conformance retention record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceRetentionV1 {
    pub retired_artifact_digest: [u8; 32],
    pub retired_artifact_kind: ConformanceArtifactKindV1,
    pub retirement_date: String,
    pub last_stable_major_at_retirement: u64,
    pub earliest_removal_date: String,
    pub earliest_removal_stable_major: u64,
    pub record_digest: [u8; 32],
}

impl ConformanceRetentionV1 {
    /// A retention record with both removal bounds and the record digest computed.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` for an invalid retirement date or a bound past the
    /// representable year or major.
    pub fn new(
        retired_artifact_digest: [u8; 32],
        retired_artifact_kind: ConformanceArtifactKindV1,
        retirement_date: &str,
        last_stable_major_at_retirement: u64,
    ) -> Result<Self, Error> {
        removal_bounds(retirement_date, last_stable_major_at_retirement).map(
            |(earliest_removal_date, earliest_removal_stable_major)| {
                let mut record = Self {
                    retired_artifact_digest,
                    retired_artifact_kind,
                    retirement_date: retirement_date.to_owned(),
                    last_stable_major_at_retirement,
                    earliest_removal_date,
                    earliest_removal_stable_major,
                    record_digest: [0; 32],
                };
                record.record_digest = record.computed_record_digest();
                record
            },
        )
    }

    /// The record digest recomputed over fields 0 through 7.
    #[must_use]
    pub fn computed_record_digest(&self) -> [u8; 32] {
        crate::governance_record_digest(self)
    }

    /// Validate every field rule, both recomputed bounds and the record digest.
    ///
    /// # Errors
    /// Returns the closed error of the first violation.
    pub fn validate(&self) -> Result<(), Error> {
        crate::governance_validate(self)
    }

    /// Encode the retention record as its canonical CRT1 bytes.
    ///
    /// # Errors
    /// Returns the validation error when the record is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, Error> {
        crate::governance_encode(self)
    }

    /// Decode and validate exact canonical CRT1 bytes.
    ///
    /// # Errors
    /// Returns the closed error for oversized, malformed, non-canonical or invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, Error> {
        crate::governance_decode(bytes)
    }

    /// Whether the retired artifact may be removed on `today` with `current_stable_major` the
    /// newest Stable major.
    ///
    /// # Errors
    /// Returns the validation error, `FieldOutOfBounds` for an invalid `today`, or
    /// `RemovalTooEarly` unless both removal bounds are met.
    pub fn check_removal(&self, today: &str, current_stable_major: u64) -> Result<(), Error> {
        self.validate()?;
        calendar_date(today).ok_or(Error::FieldOutOfBounds)?;
        if today >= self.earliest_removal_date.as_str()
            && current_stable_major >= self.earliest_removal_stable_major
        {
            Ok(())
        } else {
            Err(Error::RemovalTooEarly)
        }
    }
}

impl GovernanceRecordV1 for ConformanceRetentionV1 {
    const MAGIC: &'static str = CONFORMANCE_RETENTION_MAGIC_V1;
    const DOMAIN: &'static [u8] = b"PiglorOS.ConformanceRetention.v1";
    const BODY_FIELDS: u64 = 6;

    fn encode_body(&self, encoder: &mut GovernanceEncoder) {
        encoder.bytes(&self.retired_artifact_digest);
        encoder.uint(self.retired_artifact_kind.wire_code());
        encoder.text(&self.retirement_date);
        encoder.uint(self.last_stable_major_at_retirement);
        encoder.text(&self.earliest_removal_date);
        encoder.uint(self.earliest_removal_stable_major);
    }

    fn decode_body(body: Vec<Value>, record_digest: [u8; 32]) -> Result<Self, Error> {
        let [digest, kind, retired, last_major, removal, removal_major] =
            crate::governance_fields::<6>(body)?;
        Ok(Self {
            retired_artifact_digest: crate::governance_fixed(digest)?,
            retired_artifact_kind: crate::governance_code(
                &kind,
                ConformanceArtifactKindV1::from_wire_code,
            )?,
            retirement_date: crate::governance_text(retired)?,
            last_stable_major_at_retirement: crate::governance_uint(&last_major)?,
            earliest_removal_date: crate::governance_text(removal)?,
            earliest_removal_stable_major: crate::governance_uint(&removal_major)?,
            record_digest,
        })
    }

    fn stored_record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    fn check(&self) -> Result<(), Error> {
        removal_bounds(&self.retirement_date, self.last_stable_major_at_retirement).and_then(
            |(date, major)| {
                if date == self.earliest_removal_date && major == self.earliest_removal_stable_major
                {
                    Ok(())
                } else {
                    Err(Error::RetentionBoundMismatch)
                }
            },
        )
    }
}

/// The earliest removal date and Stable major for a retirement.
fn removal_bounds(retirement_date: &str, last_stable_major: u64) -> Result<(String, u64), Error> {
    let (year, month, day) = calendar_date(retirement_date).ok_or(Error::FieldOutOfBounds)?;
    let removal_year = year + CONFORMANCE_RETENTION_MONTHS_V1 / 12;
    let removal_major = last_stable_major
        .checked_add(CONFORMANCE_RETENTION_STABLE_MAJORS_V1)
        .ok_or(Error::FieldOutOfBounds)?;
    if removal_year > 9999 {
        return Err(Error::FieldOutOfBounds);
    }
    let removal_day = day.min(days_in_month(removal_year, month));
    Ok((
        format!("{removal_year:04}-{month:02}-{removal_day:02}"),
        removal_major,
    ))
}

/// `(year, month, day)` of an exact `YYYY-MM-DD` Gregorian date in years 0001-9999.
fn calendar_date(value: &str) -> Option<(u32, u32, u32)> {
    let number = |start: usize, end: usize| {
        value
            .get(start..end)
            .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u32>().ok())
    };
    let separated =
        value.len() == 10 && value.get(4..5) == Some("-") && value.get(7..8) == Some("-");
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    (separated
        && year >= 1
        && (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day))
    .then_some((year, month, day))
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
