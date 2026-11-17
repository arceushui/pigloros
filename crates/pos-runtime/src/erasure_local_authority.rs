//! The single-host Local/Air-Gapped erasure authority (ADR-136).
//!
//! This slice holds the composition-time verification of the installed
//! ELB1/ELB1S bundle against the profile's TPS1 anchor and the store
//! (ADR-136 §4, *Bundle*). The authority, executor, signer and driver of
//! ADR-136 §1 are later slices of the same module.

use std::sync::Arc;

use pos_core::{
    local_erasure_bundle_signing_message_v1, local_erasure_coordinator_v1, CanonicalBytes,
    ErasureInventoryPersistencePortV1, ErasureRecoveryLimitsV1, ErasureReferenceV1, EventStore,
    KeyIdentityV1, KeyRoleV1, LocalErasureBundleSignatureV1, LocalErasureBundleV1,
    LocalErasureExecutionBindingV1, OwnerIdV1, PublicKey, Signature,
    ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_crypto::signing::{verify, verifying_key_from_public_key};
use pos_store::trust_policy_registry::{tps1_signed_by_operator_v1, CurrentTrustPolicyV1};

use crate::{ClosedErasureCoordinatorAuthorityV1, ErasureCoordinatorCompositionV1};

/// The record tag of retained TPS1 evidence in the erasure object store.
const RETAINED_TPS1_TAG: &str = "TPS1";

/// The most retained TPS1 objects composition reads: the store request-head
/// cap, chosen as a fixed read bound. No admission retains a TPS1, so the
/// bound only limits the read of TPS1 objects retained by other means.
/// A store retaining more TPS1 objects cannot be checked within it and
/// stays closed with `ErasureTrustAnchorRotated`.
///
/// The read materialises the whole set: at the cap, up to this many
/// [`pos_core::ERASURE_RETAINED_OBJECT_MAX_BYTES_V1`] objects (about 4 GiB)
/// are held in memory at once. That worst case is accepted as a one-off
/// composition cost rather than adding a streaming read to the store port.
const MAX_RETAINED_TPS1: usize = ERASURE_MAX_INVENTORY_REQUESTS;

/// The closed, payload-free reasons a Local erasure composition stays
/// closed (ADR-136 §4a).
///
/// Composition fails closed on a store it cannot read: an unreadable store
/// identity or key registry is reported as [`Self::BundleMismatch`], and an
/// unreadable inventory or retained TPS1 set as
/// [`Self::ErasureTrustAnchorRotated`], indistinguishable from a store that
/// differs from the bundle or fails the Q17 rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalErasureCompositionErrorV1 {
    /// ELB1 or ELB1S is not canonical, ELB1S names another bundle, no TPS1
    /// root carries the `issued_by` key id, or the root signature is invalid.
    BundleInvalid,
    /// The bundle names another policy, executor, Local Principal registry,
    /// store identity or live signer key than this binary and store, or the
    /// store identity or key registry cannot be read.
    BundleMismatch,
    /// The installed TPS1 revokes the bundle root or the bundle signer.
    TrustRevoked,
    /// The store holds erasure requests and a retained TPS1 the currently
    /// pinned operator key cannot verify (ADR-136 Q17), or its inventory or
    /// retained TPS1 set cannot be read.
    ErasureTrustAnchorRotated,
}

impl std::fmt::Display for LocalErasureCompositionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::BundleInvalid => "local erasure bundle is invalid",
            Self::BundleMismatch => "local erasure bundle does not match this deployment",
            Self::TrustRevoked => "local erasure bundle trust is revoked",
            Self::ErasureTrustAnchorRotated => "erasure trust anchor was rotated",
        })
    }
}

impl std::error::Error for LocalErasureCompositionErrorV1 {}

/// The trusted inputs a composition root supplies to
/// [`ErasureCoordinatorCompositionV1::local`].
pub struct LocalErasureCompositionInputsV1<'a> {
    /// The installed ELB1 bytes.
    pub bundle: &'a [u8],
    /// The installed ELB1S bytes.
    pub bundle_signature: &'a [u8],
    /// The current TPS1 of the profile's deployment trust state store.
    pub trust: &'a CurrentTrustPolicyV1,
    /// The operator key pinned in the deployment release configuration
    /// (ADR-104); retained TPS1 evidence must verify under it (Q17).
    pub operator_public_key: [u8; 32],
    /// The authority registry digest of the Local Principal the store
    /// records.
    pub authority_registry_digest: ErasureReferenceV1,
    /// `CA(ELP1)` of the policy compiled into this binary.
    pub policy: ErasureReferenceV1,
    /// The composed executor, or `None` for a root that composes no
    /// executor and therefore skips the `execution_binding` check.
    pub execution_binding: Option<&'a LocalErasureExecutionBindingV1>,
}

impl ErasureCoordinatorCompositionV1 {
    /// Verify the installed Local erasure bundle (ADR-136 §4) and compose
    /// the root over it, before the host takes ownership of `store`.
    ///
    /// The bundle must be signed, over `["ELB1-SIG", 1, CA(ELB1)]`, by the
    /// current TPS1 root its `issued_by` names; neither that root nor the
    /// signer may be revoked; its Local Principal registry digest, policy,
    /// execution binding and store identity must equal this deployment's;
    /// and the key registry must hold its role-2 signer key live, not
    /// destroyed. When the store holds any erasure request, every retained
    /// TPS1 must verify under the pinned operator key.
    ///
    /// A composition only admits new work: recovery of committed evidence
    /// verifies against the retained ELB1 and TPS1, never this check.
    ///
    /// The coordinator identity is `CA("ELCOORD1", [store_identity])`. The
    /// composed authority is still the closed authority: it proves only an
    /// empty store until the `LocalErasureAuthorityV1` slice installs the
    /// verified bundle.
    ///
    /// # Errors
    /// Returns the [`LocalErasureCompositionErrorV1`] that keeps the root
    /// closed.
    pub fn local<S>(
        inputs: &LocalErasureCompositionInputsV1<'_>,
        store: &mut S,
    ) -> Result<Self, LocalErasureCompositionErrorV1>
    where
        S: ErasureInventoryPersistencePortV1 + EventStore + ?Sized,
    {
        verified_bundle(inputs)
            .and_then(|bundle| matches_store(&bundle, store).map(|()| bundle))
            .and_then(|bundle| {
                retained_trust_verifies(inputs.operator_public_key, store)
                    .then_some(bundle)
                    .ok_or(LocalErasureCompositionErrorV1::ErasureTrustAnchorRotated)
            })
            .and_then(|bundle| {
                local_erasure_coordinator_v1(bundle.store_identity)
                    .ok()
                    .and_then(|coordinator| {
                        Self::new(Arc::new(ClosedErasureCoordinatorAuthorityV1), coordinator).ok()
                    })
                    .ok_or(LocalErasureCompositionErrorV1::BundleMismatch)
            })
    }
}

/// Decode the bundle and check it against the TPS1 anchor and this
/// deployment.
///
/// ELB1 `tps1` is an issuance record and is not compared with the installed
/// TPS1, so a routine TPS1 refresh does not force re-signing the bundle.
fn verified_bundle(
    inputs: &LocalErasureCompositionInputsV1<'_>,
) -> Result<LocalErasureBundleV1, LocalErasureCompositionErrorV1> {
    let snapshot = inputs.trust.snapshot();
    LocalErasureBundleV1::from_canonical_cbor(inputs.bundle)
        .ok()
        .and_then(|bundle| bundle.reference().ok().map(|reference| (bundle, reference)))
        .and_then(|(bundle, reference)| {
            LocalErasureBundleSignatureV1::from_canonical_cbor(inputs.bundle_signature)
                .ok()
                .filter(|signature| signature.bundle == reference)
                .zip(local_erasure_bundle_signing_message_v1(reference).ok())
                .filter(|(signature, message)| root_signed(snapshot, &bundle, signature, message))
                .map(|_| bundle)
        })
        .ok_or(LocalErasureCompositionErrorV1::BundleInvalid)
        .and_then(|bundle| {
            if snapshot
                .revoked_key_ids
                .iter()
                .any(|key_id| *key_id == bundle.issued_by || *key_id == bundle.signer_key_id)
            {
                Err(LocalErasureCompositionErrorV1::TrustRevoked)
            } else {
                Ok(bundle)
            }
        })
        .and_then(|bundle| {
            let binds_deployment = bundle.authority_registry_digest
                == inputs.authority_registry_digest
                && bundle.policy == inputs.policy
                && inputs
                    .execution_binding
                    .is_none_or(|binding| *binding == bundle.execution_binding);
            binds_deployment
                .then_some(bundle)
                .ok_or(LocalErasureCompositionErrorV1::BundleMismatch)
        })
}

/// Whether the TPS1 root `issued_by` names signed `message` (ADR-136 §4:
/// TPS1 roots carry no role, so the codec-enforced `erasure-bundle/` key id
/// prefix is the purpose scope).
fn root_signed(
    snapshot: &pos_conformance::TrustPolicySnapshotV1,
    bundle: &LocalErasureBundleV1,
    signature: &LocalErasureBundleSignatureV1,
    message: &[u8],
) -> bool {
    snapshot
        .trust_roots
        .iter()
        .find(|root| root.key_id == bundle.issued_by)
        .and_then(|root| {
            verifying_key_from_public_key(&PublicKey::from_bytes(root.public_key)).ok()
        })
        .is_some_and(|key| {
            verify(
                &key,
                &CanonicalBytes::from_vec(message.to_vec()),
                &Signature::from_bytes(signature.admin_signature),
            )
            .is_ok()
        })
}

/// Check the bundle's store identity and live role-2 signer key against
/// `store`.
fn matches_store<S>(
    bundle: &LocalErasureBundleV1,
    store: &mut S,
) -> Result<(), LocalErasureCompositionErrorV1>
where
    S: ErasureInventoryPersistencePortV1 + EventStore + ?Sized,
{
    let same_store = store
        .erasure_store_identity()
        .ok()
        .flatten()
        .is_some_and(|identity| *identity.as_bytes() == bundle.store_identity.digest());
    let registered_signer = String::from_utf8(bundle.signer_identity.owner_id.clone())
        .ok()
        .and_then(|owner| OwnerIdV1::new(owner).ok())
        .zip(store.load_key_registry().ok().flatten())
        .and_then(|(owner_id, registry)| {
            registry.key_record(KeyIdentityV1::from_parts(
                owner_id,
                KeyRoleV1::TimelineIntegritySigning,
                bundle.signer_identity.epoch,
            ))
        })
        .filter(|record| record.private_material_digest.is_some())
        .and_then(|record| record.public_verification_key)
        .is_some_and(|key| *key.as_bytes() == bundle.signer_public_key);
    (same_store && registered_signer)
        .then_some(())
        .ok_or(LocalErasureCompositionErrorV1::BundleMismatch)
}

/// The ADR-136 Q17 interim rule: a store without erasure requests always
/// passes; one with requests passes only when it can be read and every
/// retained TPS1 verifies under the pinned operator key.
///
/// An empty retained set passes even when requests exist. ERQ1 pins no
/// trust revision (ADR-136 §5): submission references only ERAZ1, ELP1,
/// ELSEL1 and ELIDEM1, and no admission retains a TPS1 (a freeze retains
/// only ELB1 and ELLR1). A store with requests therefore legitimately
/// retains no TPS1, and the check refuses only a retained TPS1 that the
/// pinned operator key does not verify. Passing here admits nothing on its
/// own: this slice composes the closed authority, which proves only an
/// empty store.
fn retained_trust_verifies<S>(operator_public_key: [u8; 32], store: &mut S) -> bool
where
    S: ErasureInventoryPersistencePortV1 + ?Sized,
{
    store
        .erasure_authority_snapshot_with_limits(ErasureRecoveryLimitsV1::compiled_maximum())
        .is_ok_and(|snapshot| {
            snapshot.inventory().request_heads().is_empty()
                || store
                    .retained_erasure_objects(RETAINED_TPS1_TAG, MAX_RETAINED_TPS1)
                    .is_ok_and(|retained| {
                        retained
                            .iter()
                            .all(|tps1| tps1_signed_by_operator_v1(tps1, &operator_public_key))
                    })
        })
}
