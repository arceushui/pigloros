//! The evaluator/report trust seam of ADR-062 Revision 8 section 5.2, in two steps.
//!
//! The owner decisions of 2026-10-30 (`ADR-062_R8_Report_Attestation_Binding`) split the seam.
//! Slice G1 (#1236) defines only the two port steps the report-attestation verifier calls: key
//! admission before the signature check, which sees nothing but the role and the key id, and
//! artifact revocation after the embedded CNR1 report is parsed, which sees the report digest
//! and the evaluator binary digest from that report. Slice G2 (#1237) implements both over the
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

/// Why a conformance signing key was not admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ConformanceKeyRefusalV1 {
    /// No root of the policy has this key id.
    UnknownRoot,
    /// The key is a root for another role.
    RoleMismatch,
    /// The key is revoked.
    Revoked,
    /// The policy chain went back to a lower epoch or dropped a revocation.
    RolledBack,
    /// The policy is past its offline-valid-through position.
    SnapshotStale,
}

/// Why an attested artifact was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ConformanceArtifactRefusalV1 {
    /// The CNR1 report digest is revoked.
    RevokedReport,
    /// The evaluator binary digest is revoked.
    RevokedEvaluatorBinary,
}

/// The two trust steps of report-attestation verification.
pub trait ConformanceTrustAdmissionPortV1 {
    /// Admit `key_id` for `role` and resolve it to its verifying key.
    ///
    /// # Errors
    /// Returns the closed refusal when the key is not admitted for `role`.
    fn admit_key(
        &self,
        role: ConformanceTrustRoleV1,
        key_id: &[u8; 32],
    ) -> Result<VerifyingKey, ConformanceKeyRefusalV1>;

    /// Refuse a revoked CNR1 report digest or evaluator binary digest.
    ///
    /// # Errors
    /// Returns the closed refusal when either digest is revoked.
    fn check_artifact_revocation(
        &self,
        report_digest: &[u8; 32],
        evaluator_binary_digest: &[u8; 32],
    ) -> Result<(), ConformanceArtifactRefusalV1>;
}
