//! The evaluator/report trust-admission seam of ADR-062 Revision 8 section 5.2.
//!
//! Slice G1 (#1236) defines only the port the report-attestation verifier calls between the
//! `payloadType` check and the signature check. Slice G2 (#1237) implements it over the
//! `ConformanceTrustPolicyV1` (CTP1) record bound to TPS1; G1 tests use a test double.

use ed25519_dalek::VerifyingKey;

/// The purpose a conformance key is admitted for. CTP1 keeps a separate root list per role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ConformanceTrustRoleV1 {
    /// Signs evaluator releases.
    EvaluatorRelease,
    /// Signs conformance-report attestations.
    ReportSigning,
}

/// Why a conformance key was not admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ConformanceTrustRefusalV1 {
    /// No root of the policy has this key id.
    UnknownRoot,
    /// The key is a root for another role.
    RoleMismatch,
    /// The key or the artifact digest is revoked.
    Revoked,
    /// The policy chain went back to a lower epoch or dropped a revocation.
    RolledBack,
    /// The policy is past its offline-valid-through position.
    SnapshotStale,
}

/// Admits a key id for a role and resolves it to its verifying key.
pub trait ConformanceTrustAdmissionPortV1 {
    /// Admit `key_id` for `role` over the artifact with BLAKE3 digest `artifact_digest`.
    ///
    /// # Errors
    /// Returns the closed refusal when the key is not admitted for `role`.
    fn admit(
        &self,
        role: ConformanceTrustRoleV1,
        key_id: &[u8; 32],
        artifact_digest: &[u8; 32],
    ) -> Result<VerifyingKey, ConformanceTrustRefusalV1>;
}
