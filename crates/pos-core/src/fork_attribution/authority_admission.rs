//! ADR-105 `ImportedForkAttributionAdmissionV1` (`IFA1`).
//!
//! The immutable admission fact that an import commits and Replay reads. It
//! is derived only from an exact `FAE1` plus the admitted policy generation;
//! this value is not itself proof that any import committed.

use super::{
    array,
    authority_envelope::ForkAttributionAuthorityEnvelopeV1,
    authority_issuer::{ForkAttributionIssuerV1, MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1},
    bytes, canonical, domain_digest, hash, text, timeline, uint,
    ForkAttributionCodecErrorV1 as Error, Reader, ADMISSION_DOMAIN,
};
use crate::{Hash, TimelineId};

/// Maximum accepted canonical `IFA1` bytes, per ADR-105 r6 erratum E3.
///
/// The largest valid record, with a 128-byte issuer ID and every integer at
/// its widest, is 428 bytes.
pub const MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1: usize = 512;

/// Construction fields for one `IFA1` import admission record.
///
/// The wire layout is the 12-element array of ADR-105 r6 erratum E3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedForkAttributionAdmissionInputV1 {
    /// `IFA1` field 2: the `FAE1` import operation ID.
    pub import_operation_id: Hash,
    /// `IFA1` field 3: the primitive `FAO1` code-2 origin digest.
    pub authority_origin_digest: Hash,
    /// `IFA1` field 4: the full signed-envelope digest.
    pub full_envelope_digest: Hash,
    /// `IFA1` field 5: the exact `FAI1` issuer identity.
    pub issuer: ForkAttributionIssuerV1,
    /// `IFA1` field 6: the admitting `FIP1` digest.
    pub issuer_policy_digest: Hash,
    /// `IFA1` field 7: the admitting `FIP1` generation.
    pub issuer_policy_generation: u64,
    /// `IFA1` field 8: the child Fork Timeline ID.
    pub child_timeline_id: TimelineId,
    /// `IFA1` field 9: the final logical head.
    pub final_logical_head: u64,
    /// `IFA1` field 10: the committed closure root.
    pub closure_root: Hash,
    /// `IFA1` field 11 (revision 6): the ADR-099 digest of the carried `FAR1`.
    pub fork_admission_digest: Hash,
}

/// Strict portable `IFA1` bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedForkAttributionAdmissionV1(ImportedForkAttributionAdmissionInputV1);

impl ImportedForkAttributionAdmissionV1 {
    /// Validate one admission record.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` for any zero digest or a zero policy generation.
    pub fn new(input: ImportedForkAttributionAdmissionInputV1) -> Result<Self, Error> {
        let digests = [
            input.import_operation_id,
            input.authority_origin_digest,
            input.full_envelope_digest,
            input.issuer_policy_digest,
            input.closure_root,
            input.fork_admission_digest,
        ];
        if digests.contains(&Hash::zero()) || input.issuer_policy_generation == 0 {
            return Err(Error::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    /// Derive the admission record for one exact envelope.
    ///
    /// The child and final head come from `FTI1`, which the import seam must
    /// prove equal to `FAR1`; the `FAR1` digest is recomputed from the exact
    /// carried bytes.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` for a zero policy generation.
    pub fn from_envelope(
        envelope: &ForkAttributionAuthorityEnvelopeV1,
        issuer_policy_generation: u64,
    ) -> Result<Self, Error> {
        let unsigned = envelope.unsigned();
        let input = unsigned.input();
        let fork = &input.timeline_import;
        Self::new(ImportedForkAttributionAdmissionInputV1 {
            import_operation_id: input.import_operation_id,
            authority_origin_digest: unsigned.authority_origin_digest(),
            full_envelope_digest: envelope.full_envelope_digest(),
            issuer: input.issuer.clone(),
            issuer_policy_digest: input.issuer_policy_digest,
            issuer_policy_generation,
            child_timeline_id: fork.input().child_timeline_id,
            final_logical_head: fork.final_logical_head(),
            closure_root: unsigned.closure_root(),
            fork_admission_digest: domain_digest(ADMISSION_DOMAIN, &input.records.fork_admission),
        })
    }

    /// Return the validated `IFA1` fields.
    #[must_use]
    pub const fn input(&self) -> &ImportedForkAttributionAdmissionInputV1 {
        &self.0
    }

    /// Encode the exact twelve-field deterministic-CBOR `IFA1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(448);
        array(&mut out, 12);
        text(&mut out, "IFA1");
        uint(&mut out, 1);
        hash(&mut out, value.import_operation_id);
        hash(&mut out, value.authority_origin_digest);
        hash(&mut out, value.full_envelope_digest);
        bytes(&mut out, &value.issuer.to_canonical_cbor());
        hash(&mut out, value.issuer_policy_digest);
        uint(&mut out, value.issuer_policy_generation);
        timeline(&mut out, value.child_timeline_id);
        uint(&mut out, value.final_logical_head);
        hash(&mut out, value.closure_root);
        hash(&mut out, value.fork_admission_digest);
        out
    }

    /// Decode exact canonical `IFA1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, unsupported-version, or noncanonical bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let mut wire = Reader::new(bytes_in, MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1)?;
        wire.array(12)?;
        wire.magic("IFA1")?;
        wire.version()?;
        let record = Self::new(ImportedForkAttributionAdmissionInputV1 {
            import_operation_id: wire.hash()?,
            authority_origin_digest: wire.hash()?,
            full_envelope_digest: wire.hash()?,
            issuer: ForkAttributionIssuerV1::from_canonical_cbor(
                wire.record(MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1)?,
            )?,
            issuer_policy_digest: wire.hash()?,
            issuer_policy_generation: wire.uint()?,
            child_timeline_id: wire.timeline()?,
            final_logical_head: wire.uint()?,
            closure_root: wire.hash()?,
            fork_admission_digest: wire.hash()?,
        })?;
        wire.finish()?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}
