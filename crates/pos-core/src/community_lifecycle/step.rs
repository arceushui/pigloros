//! Input-only CPI1 producer, derived before any guest result or receipt exists.

use super::{
    digest, record_prefix, validate_horizon, CommunityLifecycleErrorV1 as Error,
    CommunityMemberBindingV1, CommunityPassKeyV1, CommunityPreparedInvocationV1, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, Hash};
use zeroize::Zeroizing;

/// Exact CPI1 fields, not proof that Reserve or an invocation actually occurred.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityInvocationStepInputV1 {
    /// Original successfully reserved pass; selection is checked by its owner.
    pub pass_key: CommunityPassKeyV1,
    /// Exact CMB1 of the prepared invocation.
    pub member_binding_digest: Hash,
    /// Original pre-Reserve fresh invocation identity.
    pub invocation_id: [u8; 16],
    /// Exact CNT1 named by that member binding.
    pub negotiated_tuple_digest: Hash,
    /// Exact full CIN1 identity, not an abbreviated input hash.
    pub prepared_invocation_digest: Hash,
    /// Original pre-Reserve CIR1 source-closure identity from CIN1.
    pub source_closure_root: Hash,
    /// Independently installed execution-provenance rule bundle.
    pub rule_bundle_digest: Hash,
    /// Original finite evidence horizon, not a renewed current timestamp.
    pub evidence_not_after_micros: u64,
}

/// Input-only step identity for CSR1, distinct from CIV1 measurements/results.
///
/// Derived from actual retained CMB1/CIN1 data, with no output, future result,
/// receipt, measurement or current-node self-reference. Data equality still
/// cannot authenticate a source, current permission or successful Reserve.
pub struct CommunityInvocationStepV1(CommunityInvocationStepInputV1);

impl CommunityInvocationStepV1 {
    /// Derive the producer from exact prepared data and the original pass.
    ///
    /// # Errors
    /// Rejects a member/State-schema/Timeline mismatch, zero rule bundle or
    /// unbounded evidence horizon. The owner must independently verify retained
    /// CNT1/profile, source closure, current authority and original reservation.
    /// Preparing this data never grants a worker-launch permit.
    pub fn new(
        pass_key: CommunityPassKeyV1,
        member: &CommunityMemberBindingV1<'_>,
        prepared: &CommunityPreparedInvocationV1<'_>,
        rule_bundle_digest: Hash,
        evidence_not_after_micros: u64,
    ) -> Result<Self> {
        let input = prepared.as_input();
        let member_digest = member.digest();
        if rule_bundle_digest == Hash::zero()
            || input.member_binding_digest != member_digest
            || input.timeline_position.timeline_id != pass_key.timeline().inner().to_bytes()
            || &input.prior_state_schema_digest != member.as_input().state_schema_digest.as_bytes()
        {
            return Err(Error::InvalidBinding);
        }
        validate_horizon(evidence_not_after_micros).map(|()| {
            Self(CommunityInvocationStepInputV1 {
                pass_key,
                member_binding_digest: member_digest,
                invocation_id: input.invocation_id,
                negotiated_tuple_digest: member.as_input().negotiated_tuple_digest,
                prepared_invocation_digest: prepared.digest(),
                source_closure_root: Hash::from_bytes(input.provenance_root),
                rule_bundle_digest,
                evidence_not_after_micros,
            })
        })
    }

    /// Borrow exact producer data; no measured output is an input of this record.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityInvocationStepInputV1 {
        &self.0
    }

    /// Encode exact10-field CPI1 into fully pre-sized zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 10, *b"CPI1");
        let pass = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &pass, 2);
        encode_hash(&mut out, input.member_binding_digest);
        encode_bytes(&mut out, &input.invocation_id, 2);
        for hash in [
            input.negotiated_tuple_digest,
            input.prepared_invocation_digest,
            input.source_closure_root,
            input.rule_bundle_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Exact CPI1 identity, independent of all later State/output/receipt hashes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CPI1.v1\0", &self.to_canonical_cbor())
    }

    /// Compare retained bytes against a producer derived from retained CMB1/CIN1.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/unknown/trailing/oversized or substituted
    /// bytes. A bare historical CPI1 hash cannot replace the required preimages.
    pub fn validate_canonical_cbor(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 1024 {
            return Err(Error::BoundsExceeded);
        }
        if bytes == self.to_canonical_cbor().as_slice() {
            Ok(())
        } else {
            Err(Error::InvalidBinding)
        }
    }
}
