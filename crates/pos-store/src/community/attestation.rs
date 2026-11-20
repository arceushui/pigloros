//! Per-request evaluation snapshot over an installed attestation set
//! (ADR-129 revision 6, P4′: R6.2(5) and R6.2(8)).
//!
//! A loaded chain is re-stamped with its authority Timeline's current
//! revocation epoch and fences, so its current bindings stop matching any
//! frozen snapshot after an unrelated revocation. The owner therefore admits
//! a chain only when every grant's **as-issued** binding is in the installed
//! attestation set, and then evaluates against a snapshot built for this one
//! request: the request's own authentication binding and the chain's current
//! bindings. Store contents are never a trust root: a grant that was not
//! attested at composition gives no snapshot.

use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityRegistrySnapshotV1, AuthorityTrustRootSealV1, CapabilityGrantV1, Hash,
    PersistedAuthorityV1, WallTime,
};
use pos_crypto::fork_authentication::VerifiedAuthenticatedPrincipalEvidenceV1;

/// The authentication result derived from one policy-verified FAE1
/// (R6.2(3)(iv)): the APR1 principal, adapter, assurance and validity, with
/// the FAE1 digest as binding digest. Only a verified witness yields one.
///
/// `seal` is the one the composition root installed the owner with; this
/// crate never mints one (#1374).
pub(super) fn authenticated_result(
    seal: &AuthorityTrustRootSealV1,
    verified: &VerifiedAuthenticatedPrincipalEvidenceV1,
) -> Option<AuthenticatedPrincipalResultV1> {
    let evidence = verified.evidence();
    let record = evidence.record();
    evidence
        .digest()
        .ok()
        .zip(AssuranceLevelV1::try_new(record.assurance).ok())
        .and_then(|(binding_digest, assurance)| {
            AuthenticatedPrincipalResultV1::try_from_draft(
                seal,
                AuthenticatedPrincipalDraftV1 {
                    principal: record.principal.clone(),
                    adapter_id: record.adapter_id.clone(),
                    assurance,
                    issued_at: WallTime::from_micros(record.issued_at),
                    expires_at: WallTime::from_micros(record.expires_at),
                    binding_digest,
                },
            )
            .ok()
        })
}

/// The snapshot one request is evaluated against, or `None` when any chain
/// grant's as-issued binding is not attested by `attestation`.
///
/// `registry_digest` is the pinned authority registry digest; the evaluator
/// still requires every grant to carry it. A revoked grant stays attested
/// and is refused by the evaluator itself.
pub(super) fn evaluation_snapshot(
    seal: &AuthorityTrustRootSealV1,
    attestation: &AuthorityRegistrySnapshotV1,
    registry_digest: Hash,
    authentication_binding: Hash,
    persisted: &PersistedAuthorityV1,
) -> Option<AuthorityRegistrySnapshotV1> {
    let attested = attestation.capability_bindings();
    persisted
        .issued_binding_digests()
        .ok()
        .filter(|issued| {
            issued
                .iter()
                .all(|binding| attested.binary_search(binding).is_ok())
        })
        .and_then(|_| {
            persisted
                .chain()
                .grants()
                .iter()
                .map(CapabilityGrantV1::binding_digest)
                .collect::<Result<Vec<_>, _>>()
                .ok()
        })
        .and_then(|mut current| {
            current.sort_unstable();
            AuthorityRegistrySnapshotV1::try_new(
                seal,
                registry_digest,
                vec![authentication_binding],
                current,
                Vec::new(),
            )
            .ok()
        })
}
