//! The evaluator/report trust seam of ADR-062 Revision 8 section 5.2, in two steps.
//!
//! The owner decisions of 2026-10-30 (`ADR-062_R8_Report_Attestation_Binding`) split the seam:
//! key admission before the signature check, which sees nothing but the role and the key id,
//! and artifact revocation after the embedded CNR1 report is parsed, which sees the report digest
//! and the evaluator binary digest from that report. Slice G1 (#1236) defined the two port steps;
//! slice G2 (#1237) implements them in [`ConformanceTrustAdmissionV1`] over a
//! [`ConformanceTrustPolicyV1`] (CTP1) chain bound to the TPS1 snapshot it extends.
//!
//! The admission is built from bytes only: the CTP1 chain, the TPS1 snapshot, the pinned
//! operator key and a trusted UTC second. Air-Gapped verification passes the bundled CTP1/TPS1
//! pair; nothing here contacts a network or an online transparency service.

use crate::conformance_trust_policy::{
    ConformanceTrustPolicyContractErrorV1, ConformanceTrustPolicyV1,
};
use crate::trust_policy_snapshot::{TrustPolicySnapshotContractErrorV1, TrustPolicySnapshotV1};
use ed25519_dalek::VerifyingKey;
use pos_crypto::dsse::key_id_v1;

/// The purpose a conformance key is admitted for. CTP1 keeps a separate root list per role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ConformanceTrustRoleV1 {
    /// Signs conformance evaluator releases (`KeyRoleV1::ConformanceEvaluatorSigning`).
    EvaluatorRelease,
    /// Signs conformance-report attestations (`KeyRoleV1::ConformanceReportSigning`).
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

/// Why a CTP1 chain and its TPS1 snapshot could not be loaded as a trust admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConformanceTrustAdmissionErrorV1 {
    /// The pinned operator key is not an Ed25519 verifying key.
    #[error("the pinned CTP1 operator key is invalid")]
    OperatorKey,
    /// A CTP1 record is not a valid canonical record.
    #[error("a CTP1 record is invalid: {0}")]
    Policy(ConformanceTrustPolicyContractErrorV1),
    /// A CTP1 operator signature does not verify under the pinned operator key.
    #[error("a CTP1 operator signature does not verify")]
    OperatorSignature,
    /// The TPS1 snapshot is not a valid canonical record.
    #[error("the TPS1 snapshot is invalid: {0}")]
    Snapshot(TrustPolicySnapshotContractErrorV1),
    /// The CTP1 chain is empty.
    #[error("the CTP1 chain is empty")]
    EmptyChain,
    /// The current CTP1 record does not extend the supplied TPS1 snapshot.
    #[error("the current CTP1 record does not extend the TPS1 snapshot")]
    SnapshotBinding,
}

/// The CTP1 implementation of [`ConformanceTrustAdmissionPortV1`].
///
/// The chain runs from the oldest policy the verifier already trusts to the current policy.
/// Along it each policy must name the BLAKE3 digest of its predecessor's exact bytes as
/// `previous_policy_digest`, have a strictly greater epoch, and keep every revocation of its
/// predecessor; otherwise every key is refused as [`ConformanceKeyRefusalV1::RolledBack`]. When
/// the trusted UTC second is not before the current policy's `offline_valid_through`, every key
/// is refused as [`ConformanceKeyRefusalV1::SnapshotStale`]. Among the keys of a standing
/// policy, a revoked key id is [`ConformanceKeyRefusalV1::Revoked`], a root of the other role is
/// [`ConformanceKeyRefusalV1::RoleMismatch`] and any other key is
/// [`ConformanceKeyRefusalV1::UnknownRoot`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceTrustAdmissionV1 {
    policy: ConformanceTrustPolicyV1,
    standing: Result<(), ConformanceKeyRefusalV1>,
}

impl ConformanceTrustAdmissionV1 {
    /// Load a CTP1 chain (oldest first, current last) and the TPS1 snapshot the current policy
    /// extends, authenticating every CTP1 record with the pinned operator key.
    ///
    /// # Errors
    /// Returns the closed [`ConformanceTrustAdmissionErrorV1`] of the first failing check, in
    /// the order of its variants.
    pub fn from_chain_v1(
        chain: &[&[u8]],
        trust_policy_snapshot: &[u8],
        operator_public_key: &[u8; 32],
        trusted_utc_second: i64,
    ) -> Result<Self, ConformanceTrustAdmissionErrorV1> {
        let operator_key = VerifyingKey::from_bytes(operator_public_key)
            .map_err(|_| ConformanceTrustAdmissionErrorV1::OperatorKey)?;
        let mut policies = chain
            .iter()
            .map(|bytes| {
                ConformanceTrustPolicyV1::from_canonical_cbor(bytes)
                    .map_err(ConformanceTrustAdmissionErrorV1::Policy)
                    .and_then(|policy| {
                        if policy.has_operator_signature(&operator_key) {
                            Ok((policy, *blake3::hash(bytes).as_bytes()))
                        } else {
                            Err(ConformanceTrustAdmissionErrorV1::OperatorSignature)
                        }
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        TrustPolicySnapshotV1::from_canonical_cbor(trust_policy_snapshot)
            .map_err(ConformanceTrustAdmissionErrorV1::Snapshot)?;
        let rolled_back = policies
            .windows(2)
            .any(|pair| !extends(&pair[0], &pair[1].0));
        let (policy, _) = policies
            .pop()
            .ok_or(ConformanceTrustAdmissionErrorV1::EmptyChain)?;
        if policy.trust_policy_snapshot_digest != *blake3::hash(trust_policy_snapshot).as_bytes() {
            return Err(ConformanceTrustAdmissionErrorV1::SnapshotBinding);
        }
        let stale = crate::parse_offline_valid_through_v1(&policy.offline_valid_through)
            .is_ok_and(|valid_through| trusted_utc_second >= valid_through);
        let standing = if rolled_back {
            Err(ConformanceKeyRefusalV1::RolledBack)
        } else if stale {
            Err(ConformanceKeyRefusalV1::SnapshotStale)
        } else {
            Ok(())
        };
        Ok(Self { policy, standing })
    }

    /// The current CTP1 policy.
    #[must_use]
    pub const fn policy(&self) -> &ConformanceTrustPolicyV1 {
        &self.policy
    }
}

/// Whether `next` extends `previous` (a policy and the digest of its exact bytes): it links to
/// those bytes, raises the epoch and keeps every revocation.
fn extends(
    (previous, previous_digest): &(ConformanceTrustPolicyV1, [u8; 32]),
    next: &ConformanceTrustPolicyV1,
) -> bool {
    let keeps = |old: &[[u8; 32]], new: &[[u8; 32]]| {
        old.iter().all(|value| new.binary_search(value).is_ok())
    };
    next.previous_policy_digest == Some(*previous_digest)
        && next.epoch > previous.epoch
        && keeps(&previous.revoked_key_ids, &next.revoked_key_ids)
        && keeps(
            &previous.revoked_evaluator_binary_digests,
            &next.revoked_evaluator_binary_digests,
        )
        && keeps(
            &previous.revoked_report_digests,
            &next.revoked_report_digests,
        )
}

impl ConformanceTrustAdmissionPortV1 for ConformanceTrustAdmissionV1 {
    fn admit_key(
        &self,
        role: ConformanceTrustRoleV1,
        key_id: &[u8; 32],
    ) -> Result<VerifyingKey, ConformanceKeyRefusalV1> {
        self.standing?;
        if self.policy.revoked_key_ids.binary_search(key_id).is_ok() {
            return Err(ConformanceKeyRefusalV1::Revoked);
        }
        let root = |role| {
            self.policy
                .roots(role)
                .iter()
                .filter_map(|key| VerifyingKey::from_bytes(key).ok())
                .find(|key| key_id_v1(key) == *key_id)
        };
        let other_role = match role {
            ConformanceTrustRoleV1::EvaluatorRelease => ConformanceTrustRoleV1::ReportSigning,
            ConformanceTrustRoleV1::ReportSigning => ConformanceTrustRoleV1::EvaluatorRelease,
        };
        root(role).ok_or_else(|| {
            if root(other_role).is_some() {
                ConformanceKeyRefusalV1::RoleMismatch
            } else {
                ConformanceKeyRefusalV1::UnknownRoot
            }
        })
    }

    fn check_artifact_revocation(
        &self,
        report_digest: &[u8; 32],
        evaluator_binary_digest: &[u8; 32],
    ) -> Result<(), ConformanceArtifactRefusalV1> {
        if self
            .policy
            .revoked_report_digests
            .binary_search(report_digest)
            .is_ok()
        {
            Err(ConformanceArtifactRefusalV1::RevokedReport)
        } else if self
            .policy
            .revoked_evaluator_binary_digests
            .binary_search(evaluator_binary_digest)
            .is_ok()
        {
            Err(ConformanceArtifactRefusalV1::RevokedEvaluatorBinary)
        } else {
            Ok(())
        }
    }
}
