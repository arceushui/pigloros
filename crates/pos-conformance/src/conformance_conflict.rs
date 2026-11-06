//! The CCF1 conformance conflict of ADR-062 Revision 8 section 5.3 (slice G3, #1238).
//!
//! A CCF1 record is the exact deterministic-CBOR array
//!
//! ```text
//! [ "CCF1", 1, kind, profile_digest, [report_digest, ...], first_coordinate / null,
//!   disclosure_digest, raised_by, epoch, resolution, resolving_profile_digest / null,
//!   record_digest ]
//! ```
//!
//! An open conflict keeps the profile Candidate. A conflict is resolved only by a new profile
//! digest: a new normative spec or fixture digest always yields a new CPF1 digest (wiki
//! `ADR-062_R8_Governance_Records`).

use crate::{
    ConformanceConflictKindV1, ConformanceConflictResolutionV1,
    ConformanceGovernanceErrorV1 as Error, GovernanceEncoder, GovernanceRecordV1,
    ProfileLifecycleV1,
};
use ciborium::value::Value;

/// Magic of the CCF1 conformance conflict record.
pub const CONFORMANCE_CONFLICT_MAGIC_V1: &str = "CCF1";
/// Most report digests one conflict names.
pub const MAX_CONFORMANCE_CONFLICT_REPORTS_V1: usize = 64;
/// Largest first canonical coordinate, as in CNR1.
pub const MAX_CONFORMANCE_CONFLICT_COORDINATE_BYTES_V1: usize = 128;

/// One CCF1 conformance conflict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceConflictV1 {
    pub kind: ConformanceConflictKindV1,
    pub profile_digest: [u8; 32],
    pub report_digests: Vec<[u8; 32]>,
    pub first_coordinate: Option<Vec<u8>>,
    pub disclosure_digest: [u8; 32],
    pub raised_by: String,
    pub epoch: u64,
    pub resolution: ConformanceConflictResolutionV1,
    pub resolving_profile_digest: Option<[u8; 32]>,
    pub record_digest: [u8; 32],
}

impl ConformanceConflictV1 {
    /// The record digest recomputed over fields 0 through 10.
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

    /// Encode the conflict as its canonical CCF1 bytes.
    ///
    /// # Errors
    /// Returns the validation error when the conflict is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, Error> {
        crate::governance_encode(self)
    }

    /// Decode and validate exact canonical CCF1 bytes.
    ///
    /// # Errors
    /// Returns the closed error for oversized, malformed, non-canonical or invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, Error> {
        crate::governance_decode(bytes)
    }

    /// Whether the conflicted profile may hold `target`: an open conflict refuses Stable.
    ///
    /// # Errors
    /// Returns the validation error, or `OpenConflict` for Stable while the conflict is open.
    pub fn admits_lifecycle(&self, target: ProfileLifecycleV1) -> Result<(), Error> {
        self.validate().and_then(|()| {
            if self.resolution == ConformanceConflictResolutionV1::Open
                && target == ProfileLifecycleV1::Stable
            {
                Err(Error::OpenConflict)
            } else {
                Ok(())
            }
        })
    }
}

impl GovernanceRecordV1 for ConformanceConflictV1 {
    const MAGIC: &'static str = CONFORMANCE_CONFLICT_MAGIC_V1;
    const DOMAIN: &'static [u8] = b"PiglorOS.ConformanceConflict.v1";
    const BODY_FIELDS: u64 = 9;

    fn encode_body(&self, encoder: &mut GovernanceEncoder) {
        encoder.uint(self.kind.wire_code());
        encoder.bytes(&self.profile_digest);
        encoder.digests(&self.report_digests);
        encoder.optional(self.first_coordinate.as_deref(), GovernanceEncoder::bytes);
        encoder.bytes(&self.disclosure_digest);
        encoder.text(&self.raised_by);
        encoder.uint(self.epoch);
        encoder.uint(self.resolution.wire_code());
        encoder.optional(
            self.resolving_profile_digest
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            GovernanceEncoder::bytes,
        );
    }

    fn decode_body(body: Vec<Value>, record_digest: [u8; 32]) -> Result<Self, Error> {
        let [kind, profile, reports, coordinate, disclosure, raised_by, epoch, rest @ ..] =
            crate::governance_fields::<9>(body)?;
        let [resolution, resolving] = rest;
        Ok(Self {
            kind: crate::governance_code(&kind, ConformanceConflictKindV1::from_wire_code)?,
            profile_digest: crate::governance_fixed(profile)?,
            report_digests: crate::governance_digests(reports)?,
            first_coordinate: crate::governance_optional(coordinate, crate::governance_bytes)?,
            disclosure_digest: crate::governance_fixed(disclosure)?,
            raised_by: crate::governance_text(raised_by)?,
            epoch: crate::governance_uint(&epoch)?,
            resolution: crate::governance_code(
                &resolution,
                ConformanceConflictResolutionV1::from_wire_code,
            )?,
            resolving_profile_digest: crate::governance_optional(
                resolving,
                crate::governance_fixed,
            )?,
            record_digest,
        })
    }

    fn stored_record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    fn check(&self) -> Result<(), Error> {
        if self.report_digests.is_empty()
            || self.report_digests.len() > MAX_CONFORMANCE_CONFLICT_REPORTS_V1
            || self.first_coordinate.as_ref().is_some_and(|coordinate| {
                coordinate.len() > MAX_CONFORMANCE_CONFLICT_COORDINATE_BYTES_V1
            })
            || !crate::governance_identifier(&self.raised_by)
        {
            return Err(Error::FieldOutOfBounds);
        }
        crate::governance_epoch(self.epoch)?;
        if !crate::strictly_ordered(&self.report_digests) {
            return Err(Error::NonCanonicalOrder);
        }
        match (self.resolution, self.resolving_profile_digest) {
            (ConformanceConflictResolutionV1::Open, None) => Ok(()),
            (ConformanceConflictResolutionV1::ResolvedByNewProfileDigest, Some(digest))
                if digest != self.profile_digest =>
            {
                Ok(())
            }
            _ => Err(Error::InvalidResolution),
        }
    }
}
