//! The CWV1 conformance waiver of ADR-062 Revision 8 section 5.3 (slice G3, #1238).
//!
//! A CWV1 record is the exact deterministic-CBOR array
//!
//! ```text
//! [ "CWV1", 1, waiver_id, profile_digest, case_id, mode, claim_layer, reason_code,
//!   rationale_digest, [approver_id, ...], conflict_disclosure_digest, issued_epoch,
//!   expiry_epoch, previous_waiver_digest / null, record_digest ]
//! ```
//!
//! A waiver on a mandatory case is only a Candidate exception and can never satisfy Stable
//! (wiki `ADR-062_R8_Governance_Records`).

use crate::{
    ClaimLayerV1, ConformanceGovernanceErrorV1 as Error, ConformanceProfileV1,
    ConformanceWaiverReasonV1, ExecutionModeV1, GovernanceEncoder, GovernanceRecordV1,
    ProfileLifecycleV1,
};
use ciborium::value::Value;

/// Magic of the CWV1 conformance waiver record.
pub const CONFORMANCE_WAIVER_MAGIC_V1: &str = "CWV1";

/// What an in-force waiver may document for a target lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceWaiverEffectV1 {
    /// A waived mandatory case: an exception of a Candidate profile only.
    CandidateException,
    /// A waived non-mandatory case: a documented exception at any lifecycle.
    DocumentedException,
}

/// One CWV1 conformance waiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceWaiverV1 {
    pub waiver_id: String,
    pub profile_digest: [u8; 32],
    pub case_id: String,
    pub mode: ExecutionModeV1,
    pub claim_layer: ClaimLayerV1,
    pub reason: ConformanceWaiverReasonV1,
    pub rationale_digest: [u8; 32],
    pub approver_ids: Vec<String>,
    pub conflict_disclosure_digest: [u8; 32],
    pub issued_epoch: u64,
    pub expiry_epoch: u64,
    /// The record digest of the waiver this one renews.
    pub previous_waiver_digest: Option<[u8; 32]>,
    pub record_digest: [u8; 32],
}

impl ConformanceWaiverV1 {
    /// The record digest recomputed over fields 0 through 13.
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

    /// Encode the waiver as its canonical CWV1 bytes.
    ///
    /// # Errors
    /// Returns the validation error when the waiver is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, Error> {
        crate::governance_encode(self)
    }

    /// Decode and validate exact canonical CWV1 bytes.
    ///
    /// # Errors
    /// Returns the closed error for oversized, malformed, non-canonical or invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, Error> {
        crate::governance_decode(bytes)
    }

    /// What this waiver documents for `profile` moving to `target` at `epoch`.
    ///
    /// The profile is the authenticated CPF1 the caller already holds. A waiver on a mandatory
    /// case is accepted only for a Candidate target, so it never satisfies Stable.
    ///
    /// # Errors
    /// Returns the validation error, then `ProfileMismatch`, `CaseNotInProfile`,
    /// `WaiverNotInForce` or `MandatoryWaiverOutsideCandidate`.
    pub fn effect(
        &self,
        profile: &ConformanceProfileV1,
        target: ProfileLifecycleV1,
        epoch: u64,
    ) -> Result<ConformanceWaiverEffectV1, Error> {
        self.validate()?;
        if profile.profile_digest != self.profile_digest {
            return Err(Error::ProfileMismatch);
        }
        let fixture = profile
            .fixtures
            .iter()
            .find(|fixture| {
                fixture.case_id == self.case_id
                    && fixture.claim_layer == self.claim_layer
                    && fixture.modes.contains(&self.mode)
            })
            .ok_or(Error::CaseNotInProfile)?;
        if !(self.issued_epoch..self.expiry_epoch).contains(&epoch) {
            return Err(Error::WaiverNotInForce);
        }
        match (fixture.mandatory, target) {
            (false, _) => Ok(ConformanceWaiverEffectV1::DocumentedException),
            (true, ProfileLifecycleV1::Candidate) => {
                Ok(ConformanceWaiverEffectV1::CandidateException)
            }
            (true, _) => Err(Error::MandatoryWaiverOutsideCandidate),
        }
    }
}

impl GovernanceRecordV1 for ConformanceWaiverV1 {
    const MAGIC: &'static str = CONFORMANCE_WAIVER_MAGIC_V1;
    const DOMAIN: &'static [u8] = b"PiglorOS.ConformanceWaiver.v1";
    const BODY_FIELDS: u64 = 12;

    fn encode_body(&self, encoder: &mut GovernanceEncoder) {
        encoder.text(&self.waiver_id);
        encoder.bytes(&self.profile_digest);
        encoder.text(&self.case_id);
        encoder.uint(u64::from(self.mode.wire_code()));
        encoder.uint(u64::from(self.claim_layer.wire_code()));
        encoder.uint(self.reason.wire_code());
        encoder.bytes(&self.rationale_digest);
        encoder.texts(&self.approver_ids);
        encoder.bytes(&self.conflict_disclosure_digest);
        encoder.uint(self.issued_epoch);
        encoder.uint(self.expiry_epoch);
        encoder.optional(
            self.previous_waiver_digest
                .as_ref()
                .map(<[u8; 32]>::as_slice),
            GovernanceEncoder::bytes,
        );
    }

    fn decode_body(body: Vec<Value>, record_digest: [u8; 32]) -> Result<Self, Error> {
        let [waiver_id, profile, case_id, mode, layer, reason, rationale, rest @ ..] =
            crate::governance_fields::<12>(body)?;
        let [approvers, disclosure, issued, expiry, previous] = rest;
        Ok(Self {
            waiver_id: crate::governance_text(waiver_id)?,
            profile_digest: crate::governance_fixed(profile)?,
            case_id: crate::governance_text(case_id)?,
            mode: crate::governance_code(&mode, crate::governance_mode)?,
            claim_layer: crate::governance_code(&layer, crate::governance_claim_layer)?,
            reason: crate::governance_code(&reason, ConformanceWaiverReasonV1::from_wire_code)?,
            rationale_digest: crate::governance_fixed(rationale)?,
            approver_ids: crate::governance_texts(approvers)?,
            conflict_disclosure_digest: crate::governance_fixed(disclosure)?,
            issued_epoch: crate::governance_uint(&issued)?,
            expiry_epoch: crate::governance_uint(&expiry)?,
            previous_waiver_digest: crate::governance_optional(previous, crate::governance_fixed)?,
            record_digest,
        })
    }

    fn stored_record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    fn check(&self) -> Result<(), Error> {
        if !crate::governance_identifier(&self.waiver_id)
            || !crate::governance_utf8_id(&self.case_id)
        {
            return Err(Error::FieldOutOfBounds);
        }
        crate::governance_approvers(&self.approver_ids)?;
        crate::governance_epoch(self.issued_epoch)?;
        if self.expiry_epoch > self.issued_epoch {
            Ok(())
        } else {
            Err(Error::ExpiryNotAfterIssue)
        }
    }
}
