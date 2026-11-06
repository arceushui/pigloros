//! The CPR1 conformance promotion record of ADR-062 Revision 8 section 5.3 (slice G3, #1238).
//!
//! A CPR1 record is the exact deterministic-CBOR array
//!
//! ```text
//! [ "CPR1", 1, profile_digest, from_lifecycle, to_lifecycle, first_report_digest,
//!   second_report_digest, first_implementation, second_implementation,
//!   shared_code_audit_digest, waiver_conflict_snapshot_digest, [approver_id, ...], epoch,
//!   record_digest ]
//! ```
//!
//! The implementations are exact CNR1 `ImplementationIdentityV1` arrays in the order of the
//! strictly ascending report digests. This slice validates the shape only; the promotion gate
//! is slice G4 (#1239).

use crate::{
    ConformanceGovernanceErrorV1 as Error, GovernanceEncoder, GovernanceRecordV1,
    ImplementationIdentityV1, ProfileLifecycleV1,
};
use ciborium::value::Value;

/// Magic of the CPR1 conformance promotion record.
pub const CONFORMANCE_PROMOTION_MAGIC_V1: &str = "CPR1";

/// One CPR1 conformance promotion record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformancePromotionV1 {
    pub profile_digest: [u8; 32],
    pub from_lifecycle: ProfileLifecycleV1,
    pub to_lifecycle: ProfileLifecycleV1,
    pub first_report_digest: [u8; 32],
    pub second_report_digest: [u8; 32],
    pub first_implementation: ImplementationIdentityV1,
    pub second_implementation: ImplementationIdentityV1,
    pub shared_code_audit_digest: [u8; 32],
    pub waiver_conflict_snapshot_digest: [u8; 32],
    pub approver_ids: Vec<String>,
    pub epoch: u64,
    pub record_digest: [u8; 32],
}

impl ConformancePromotionV1 {
    /// The record digest recomputed over fields 0 through 12.
    #[must_use]
    pub fn computed_record_digest(&self) -> [u8; 32] {
        crate::governance_record_digest(self)
    }

    /// Validate the record shape and the record digest.
    ///
    /// # Errors
    /// Returns the closed error of the first violation.
    pub fn validate(&self) -> Result<(), Error> {
        crate::governance_validate(self)
    }

    /// Encode the promotion as its canonical CPR1 bytes.
    ///
    /// # Errors
    /// Returns the validation error when the record is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, Error> {
        crate::governance_encode(self)
    }

    /// Decode and validate exact canonical CPR1 bytes.
    ///
    /// # Errors
    /// Returns the closed error for oversized, malformed, non-canonical or invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, Error> {
        crate::governance_decode(bytes)
    }
}

impl GovernanceRecordV1 for ConformancePromotionV1 {
    const MAGIC: &'static str = CONFORMANCE_PROMOTION_MAGIC_V1;
    const DOMAIN: &'static [u8] = b"PiglorOS.ConformancePromotion.v1";
    const BODY_FIELDS: u64 = 11;

    fn encode_body(&self, encoder: &mut GovernanceEncoder) {
        encoder.bytes(&self.profile_digest);
        encoder.uint(self.from_lifecycle.wire_code());
        encoder.uint(self.to_lifecycle.wire_code());
        encoder.bytes(&self.first_report_digest);
        encoder.bytes(&self.second_report_digest);
        encode_identity(encoder, &self.first_implementation);
        encode_identity(encoder, &self.second_implementation);
        encoder.bytes(&self.shared_code_audit_digest);
        encoder.bytes(&self.waiver_conflict_snapshot_digest);
        encoder.texts(&self.approver_ids);
        encoder.uint(self.epoch);
    }

    fn decode_body(body: Vec<Value>, record_digest: [u8; 32]) -> Result<Self, Error> {
        let [profile, from, to, first_report, second_report, first, second, rest @ ..] =
            crate::governance_fields::<11>(body)?;
        let [audit, snapshot, approvers, epoch] = rest;
        Ok(Self {
            profile_digest: crate::governance_fixed(profile)?,
            from_lifecycle: crate::governance_code(&from, ProfileLifecycleV1::from_wire_code)?,
            to_lifecycle: crate::governance_code(&to, ProfileLifecycleV1::from_wire_code)?,
            first_report_digest: crate::governance_fixed(first_report)?,
            second_report_digest: crate::governance_fixed(second_report)?,
            first_implementation: decode_identity(first)?,
            second_implementation: decode_identity(second)?,
            shared_code_audit_digest: crate::governance_fixed(audit)?,
            waiver_conflict_snapshot_digest: crate::governance_fixed(snapshot)?,
            approver_ids: crate::governance_texts(approvers)?,
            epoch: crate::governance_uint(&epoch)?,
            record_digest,
        })
    }

    fn stored_record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    fn check(&self) -> Result<(), Error> {
        if !matches!(
            (self.from_lifecycle, self.to_lifecycle),
            (ProfileLifecycleV1::Draft, ProfileLifecycleV1::Candidate)
                | (ProfileLifecycleV1::Candidate, ProfileLifecycleV1::Stable)
        ) {
            return Err(Error::InvalidLifecycleTransition);
        }
        if !valid_identity(&self.first_implementation)
            || !valid_identity(&self.second_implementation)
        {
            return Err(Error::FieldOutOfBounds);
        }
        crate::governance_approvers(&self.approver_ids)?;
        crate::governance_epoch(self.epoch)?;
        if self.first_report_digest < self.second_report_digest {
            Ok(())
        } else {
            Err(Error::NonCanonicalOrder)
        }
    }
}

fn valid_identity(identity: &ImplementationIdentityV1) -> bool {
    crate::governance_utf8_id(&identity.implementation_id)
        && identity
            .organization_id
            .as_deref()
            .is_none_or(crate::governance_utf8_id)
}

fn encode_identity(encoder: &mut GovernanceEncoder, identity: &ImplementationIdentityV1) {
    encoder.open_array(6);
    encoder.text(&identity.implementation_id);
    encoder.bytes(&identity.source_digest);
    encoder.bytes(&identity.build_digest);
    encoder.bytes(&identity.binary_digest);
    encoder.bytes(&identity.public_contract_digest);
    encoder.optional(identity.organization_id.as_deref(), GovernanceEncoder::text);
}

fn decode_identity(value: Value) -> Result<ImplementationIdentityV1, Error> {
    let [id, source, build, binary, contract, organization] =
        crate::governance_fields::<6>(crate::governance_array(value)?)?;
    Ok(ImplementationIdentityV1 {
        implementation_id: crate::governance_text(id)?,
        source_digest: crate::governance_fixed(source)?,
        build_digest: crate::governance_fixed(build)?,
        binary_digest: crate::governance_fixed(binary)?,
        public_contract_digest: crate::governance_fixed(contract)?,
        organization_id: crate::governance_optional(organization, crate::governance_text)?,
    })
}
