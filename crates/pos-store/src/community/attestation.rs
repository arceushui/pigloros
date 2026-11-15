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

use pos_core::{AuthorityRegistrySnapshotV1, CapabilityGrantV1, Hash, PersistedAuthorityV1};

/// The snapshot one request is evaluated against, or `None` when any chain
/// grant's as-issued binding is not attested by `attestation`.
///
/// `registry_digest` is the pinned authority registry digest; the evaluator
/// still requires every grant to carry it. A revoked grant stays attested
/// and is refused by the evaluator itself.
pub(super) fn evaluation_snapshot(
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
                registry_digest,
                vec![authentication_binding],
                current,
                Vec::new(),
            )
            .ok()
        })
}
