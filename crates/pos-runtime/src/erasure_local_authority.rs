//! The single-host Local/Air-Gapped erasure authority (ADR-136).
//!
//! This module holds the ELP1 policy and the executor binding (ELEXV1)
//! compiled into this binary, the composition-time verification of the
//! installed ELB1/ELB1S bundle against the profile's TPS1 anchor and the
//! store (ADR-136 §4, *Bundle*) with its routine-rotation and compromise
//! rules (§5), the verify-only `LocalErasureAuthorityV1` that composition
//! installs over the verified bundle, from submission through freeze to
//! attempt, acknowledgement and receipt admission, the
//! `LocalErasureExecutorV1` that runs the owner work of dispatched
//! commands, the role-2 `LocalErasureSignerV1` that re-derives every
//! preimage before it signs, and `LocalErasureDriverV1`, the only lifecycle
//! caller.
//!
//! Before every freeze the driver's preparation retains the installed TPS1
//! and the bundle's ELB1S beside ELB1 and ELLR1 (ADR-136 Q9). ELTA1, the
//! operator-key lookup hint, is not retained yet: it needs the append-only
//! operator-key history #448 has to deliver first (ADR-136 Q17).

mod authority;
mod binding;
mod destruction;
mod driver;
mod executor;
mod freeze;
mod lifecycle;
mod policy;
mod signer;

use std::sync::Arc;

use pos_core::{
    local_erasure_bundle_signing_message_v1, local_erasure_coordinator_v1,
    local_erasure_host_timeline_v1, local_erasure_signer_key_id_v1, CanonicalBytes,
    ErasureInventoryPersistencePortV1, ErasurePersistencePortV1, ErasureRecordedAttemptReadV1,
    ErasureRecoveryLimitsV1, ErasureReferenceV1, EventStore, Hash, KeyIdentityV1, KeyRoleV1,
    LocalErasureBundleSignatureV1, LocalErasureBundleV1, LocalErasureExecutionBindingV1, OwnerIdV1,
    PublicKey, Signature, TimelineId, ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_crypto::signing::{verify, verifying_key_from_public_key};
use pos_store::trust_policy_registry::{tps1_signed_by_operator_v1, CurrentTrustPolicyV1};

use crate::erasure_host::{LocalErasurePreparationV1, LocalErasureSubmissionBindingV1};
use crate::ErasureCoordinatorCompositionV1;
use authority::LocalErasureAuthorityV1;

pub use binding::{
    local_erasure_execution_binding_v1, LOCAL_ERASURE_EXECUTOR_ID_V1,
    LOCAL_ERASURE_EXECUTOR_VERSION_DIGEST_V1, LOCAL_ERASURE_EXECUTOR_VERSION_V1,
};
pub use driver::{
    LocalErasureAdvanceV1, LocalErasureDriverV1, LocalErasureStepV1, LocalErasureSweepV1,
};
pub use executor::LocalErasureExecutorV1;
pub use policy::{
    compiled_local_erasure_policy_v1, LocalErasureClassificationRowV1,
    LOCAL_ERASURE_AUTO_RETRY_MAX_V1, LOCAL_ERASURE_CLASSIFICATION_COUNT_V1,
    LOCAL_ERASURE_CLASSIFICATION_V1, LOCAL_ERASURE_MAX_REPREPARE_V1,
    LOCAL_ERASURE_POLICY_REFERENCE_V1, LOCAL_ERASURE_QUOTA_ATTEMPTS_V1,
    LOCAL_ERASURE_STORE_REQUEST_RESERVE_V1,
};
pub use signer::{LocalErasureSignerV1, LocalErasureSigningRequestV1};

/// The record tag of retained TPS1 evidence in the erasure object store.
const RETAINED_TPS1_TAG: &str = "TPS1";

/// The most retained TPS1 objects composition reads: the store request-head
/// cap, chosen as a fixed read bound. Each freeze retains the TPS1 installed
/// at its preparation, and the store is content-addressed, so the set holds
/// one object per installed TPS1 that froze a request. A store retaining
/// more TPS1 objects cannot be checked within it and stays closed with
/// `ErasureTrustAnchorRotated`.
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
    /// The bundle names another policy than the one compiled into this
    /// binary, or another executor, Local Principal registry, store identity
    /// or live signer key than this deployment and store, its
    /// `host_timelines` omit the store's Erasure Host Timeline, the store
    /// identity, key registry or pinned trust cannot be read, or it is a
    /// routine rotation refused while a request pins another bundle the
    /// installed TPS1 does not revoke (owner decision Q12 on #1431).
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
    /// The composed executor, or `None` for a root that composes no
    /// executor and therefore skips the `execution_binding` check.
    pub execution_binding: Option<&'a LocalErasureExecutionBindingV1>,
    /// The leaf grant id of the Local Principal's root grant.
    pub principal_grant: Hash,
    /// The authority Timeline the root grant is issued on.
    pub authority_timeline: TimelineId,
    /// The clock new admissions read, in Unix seconds (UTC): an expired
    /// TPS1 or bundle closes new admissions only.
    pub clock: fn() -> u64,
}

impl ErasureCoordinatorCompositionV1 {
    /// Verify the installed Local erasure bundle (ADR-136 §4) and compose
    /// the root over it, before the host takes ownership of `store`.
    ///
    /// The bundle must be signed, over `["ELB1-SIG", 1, CA(ELB1)]`, by the
    /// current TPS1 root its `issued_by` names; neither that root nor the
    /// signer may be revoked; its policy must be
    /// [`compiled_local_erasure_policy_v1`]; its Local Principal registry
    /// digest, execution binding and store identity must equal this
    /// deployment's; its `host_timelines` must list the Erasure Host
    /// Timeline of its store identity
    /// ([`pos_core::local_erasure_host_timeline_v1`]), the fence of key
    /// destruction for erasure; and the key registry must hold its role-2
    /// signer key live, not destroyed. A routine rotation is refused while
    /// any request pins another bundle: a frozen request before its first
    /// attempt pins the bundle its obligation set names, and a request with
    /// an active attempt the bundle that attempt names. A compromise is
    /// always accepted: a pinned bundle whose root or signer the installed
    /// TPS1 revokes can never sign again, so it does not hold the rotation
    /// back (ADR-136 §5). Expiry is no revocation: a request pinning an
    /// expired bundle blocks a routine rotation until the TPS1 revokes that
    /// bundle's root or signer (Q12). When the store holds any erasure request, every
    /// retained TPS1 must verify under the pinned operator key.
    ///
    /// A composition only admits new work: recovery of committed evidence
    /// verifies against the ELB1 it pins by reference, never this check.
    ///
    /// The coordinator identity is `CA("ELCOORD1", [store_identity])`. The
    /// composed authority is `LocalErasureAuthorityV1` over the verified
    /// bundle, and the composition carries the Local submission inputs the
    /// host's `submit_local_erasure` needs.
    ///
    /// # Errors
    /// Returns the [`LocalErasureCompositionErrorV1`] that keeps the root
    /// closed.
    pub fn local<S>(
        inputs: &LocalErasureCompositionInputsV1<'_>,
        store: &mut S,
    ) -> Result<Self, LocalErasureCompositionErrorV1>
    where
        S: ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1 + EventStore + ?Sized,
    {
        let revoked = &inputs.trust.snapshot().revoked_key_ids;
        verified_bundle(inputs)
            .and_then(|bundle| matches_store(&bundle, store).map(|()| bundle))
            .and_then(lists_its_host_timeline)
            .and_then(|bundle| {
                rotation_admitted(&bundle, revoked, store)
                    .then_some(bundle)
                    .ok_or(LocalErasureCompositionErrorV1::BundleMismatch)
            })
            .and_then(|bundle| {
                retained_trust_verifies(inputs.operator_public_key, store)
                    .then_some(bundle)
                    .ok_or(LocalErasureCompositionErrorV1::ErasureTrustAnchorRotated)
            })
            .and_then(|bundle| {
                local_erasure_coordinator_v1(bundle.store_identity)
                    .ok()
                    .and_then(|coordinator| {
                        let authority = Arc::new(LocalErasureAuthorityV1 {
                            bundle_reference: bundle.reference().ok(),
                            bundle,
                            trust_expiry: inputs.trust.expiry(),
                            revoked_key_ids: revoked.clone(),
                            retained_trust: vec![
                                inputs.trust.bytes().to_vec(),
                                inputs.bundle_signature.to_vec(),
                            ],
                            clock: inputs.clock,
                            principal_grant: inputs.principal_grant,
                            authority_timeline: inputs.authority_timeline,
                        });
                        let binding = LocalErasureSubmissionBindingV1 {
                            principal_grant: inputs.principal_grant,
                            authority_timeline: inputs.authority_timeline,
                            authority_registry_digest: authority.bundle.authority_registry_digest,
                            policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
                            store_request_reserve: LOCAL_ERASURE_STORE_REQUEST_RESERVE_V1,
                            preparation: Arc::clone(&authority)
                                as Arc<dyn LocalErasurePreparationV1>,
                        };
                        Self::new(authority, coordinator)
                            .ok()
                            .map(|composition| composition.with_local_submission(binding))
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
                && bundle.policy == LOCAL_ERASURE_POLICY_REFERENCE_V1
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

/// The bundle must list its store's Erasure Host Timeline, the fence of key
/// destruction for erasure, among its host Timelines (owner decision Q14 of
/// 2026-11-17 on #1412).
fn lists_its_host_timeline(
    bundle: LocalErasureBundleV1,
) -> Result<LocalErasureBundleV1, LocalErasureCompositionErrorV1> {
    local_erasure_host_timeline_v1(bundle.store_identity)
        .is_ok_and(|host| bundle.host_timelines.binary_search(&host).is_ok())
        .then_some(bundle)
        .ok_or(LocalErasureCompositionErrorV1::BundleMismatch)
}

/// The ADR-136 Q17 interim rule: a store without erasure requests always
/// passes; one with requests passes only when it can be read and every
/// retained TPS1 verifies under the pinned operator key.
///
/// An empty retained set passes even when requests exist. ERQ1 pins no
/// trust revision (ADR-136 §5): submission references only ERAZ1, ELP1,
/// ELSEL1 and ELIDEM1, and only a freeze retains a TPS1, the one installed
/// at its preparation. A store whose requests are not frozen therefore
/// legitimately retains no TPS1, and the check refuses only a retained TPS1
/// that the pinned operator key does not verify. A committed freeze pins its trust
/// as `CA(ELB1)`, and recovery resolves only that ELB1 by reference: the
/// verified bundle, or after a rotation the retained ELB1 bytes. Recovery
/// resolves no TPS1, so retained TPS1 bytes are checked only here. Passing
/// here only lets the root compose: every admission of the composed
/// authority still applies its own trust, bundle and grant checks.
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

/// The ADR-136 §5 rotation rule: `bundle` is admitted unless a request pins
/// another bundle that the installed TPS1 does not revoke (owner decision
/// Q12 on #1431). A store whose inventory or pinned trust cannot be read
/// admits no rotation.
fn rotation_admitted<S>(bundle: &LocalErasureBundleV1, revoked: &[String], store: &mut S) -> bool
where
    S: ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1 + ?Sized,
{
    bundle.reference().is_ok_and(|current| {
        bundle_pins(store, revoked).is_some_and(|pins| {
            pins.iter()
                .all(|&(trust, revoked)| trust == current || revoked)
        })
    })
}

/// Every bundle a request of the store pins, each with whether the
/// installed TPS1 revokes its root or signer; `None` when the inventory or
/// a pinned trust cannot be read.
fn bundle_pins<S>(store: &mut S, revoked: &[String]) -> Option<Vec<(ErasureReferenceV1, bool)>>
where
    S: ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1 + ?Sized,
{
    store
        .erasure_authority_snapshot_with_limits(ErasureRecoveryLimitsV1::compiled_maximum())
        .ok()
        .and_then(|snapshot| {
            snapshot
                .inventory()
                .request_heads()
                .iter()
                .map(|(request, _)| pinned_trust(&*store, *request).ok())
                .collect::<Option<Vec<_>>>()
        })
        .map(|pins| {
            pins.into_iter()
                .flatten()
                .map(|trust| (trust, pins_revoked_bundle(&*store, trust, revoked)))
                .collect()
        })
}

/// How `provision-local-erasure` registers a role-2 signer key that
/// differs from the one the key registry holds for its owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalErasureSignerRotationV1 {
    /// A routine rotation: allowed only while no request pins a bundle.
    Routine,
    /// A compromise: allowed only once the installed TPS1 revokes the old
    /// signer key and the root or signer of every pinned bundle.
    Compromise,
}

/// Why a role-2 signer key may not be registered on an erasure store
/// (owner decision of 2026-11-18 on #1431).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalErasureRotationRefusalV1 {
    /// A routine rotation while a request pins a bundle, or a store whose
    /// pins cannot be read.
    Pinned,
    /// A compromise the installed TPS1 does not reflect: the old signer
    /// key or a pinned bundle is not revoked.
    NotRevoked,
    /// The key registry cannot be read, or its current signer record of
    /// the owner carries no public key, so the old signer is unknown.
    SignerUnknown,
}

impl std::fmt::Display for LocalErasureRotationRefusalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Pinned => "an erasure request pins the current signer's bundle",
            Self::NotRevoked => "the installed TPS1 does not revoke the old signer's bundle",
            Self::SignerUnknown => {
                "the key registry or its current signer's public key cannot be read"
            }
        })
    }
}

impl std::error::Error for LocalErasureRotationRefusalV1 {}

/// Whether the store may register `signer_public_key` as a role-2 signer
/// key of `owner` (owner decision of 2026-11-18 on #1431).
///
/// Registering a new epoch makes it the registry's only active signing key
/// for its owner, so the old signer can sign nothing more, not even for a
/// request pinned to its bundle. The key the registry holds at the
/// owner's highest epoch (an exact re-run), or the owner's first key, is
/// always allowed. Any other key is a rotation:
/// - a routine rotation is refused while any request pins a bundle (the
///   `local()` pin rule, ADR-136 §5);
/// - a compromise is allowed only when the installed TPS1, whose revoked
///   key ids are `revoked`, revokes the old signer key and the root or
///   signer of every pinned bundle.
///
/// A key registry that cannot be read, or whose current signer record of
/// the owner carries no public key, fails closed: the old signer is
/// unknown, so nothing is registered.
///
/// # Errors
/// [`LocalErasureRotationRefusalV1::Pinned`] for a routine rotation while
/// a request pins a bundle, or when the pins cannot be read;
/// [`LocalErasureRotationRefusalV1::NotRevoked`] for a compromise the
/// installed TPS1 does not reflect;
/// [`LocalErasureRotationRefusalV1::SignerUnknown`] when the key registry
/// cannot be read or its current signer record carries no public key.
pub fn local_erasure_signer_rotation_v1<S>(
    store: &mut S,
    owner: OwnerIdV1,
    signer_public_key: [u8; 32],
    rotation: LocalErasureSignerRotationV1,
    revoked: &[String],
) -> Result<(), LocalErasureRotationRefusalV1>
where
    S: ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1 + EventStore + ?Sized,
{
    store
        .load_key_registry()
        .ok()
        .ok_or(LocalErasureRotationRefusalV1::SignerUnknown)
        .and_then(|registry| {
            registry
                .and_then(|registry| {
                    registry
                        .key_records()
                        .filter(|record| {
                            record.identity.owner_id == owner
                                && record.identity.role == KeyRoleV1::TimelineIntegritySigning
                        })
                        .max_by_key(|record| record.identity.epoch)
                })
                .map_or(Ok(()), |record| {
                    record
                        .public_verification_key
                        .map(|key| *key.as_bytes())
                        .ok_or(LocalErasureRotationRefusalV1::SignerUnknown)
                        .and_then(|old| {
                            if old == signer_public_key {
                                Ok(())
                            } else {
                                rotation_refusal(store, old, rotation, revoked)
                            }
                        })
                })
        })
}

/// The rotation rule for a signer key other than `old`, the owner's
/// current one.
fn rotation_refusal<S>(
    store: &mut S,
    old: [u8; 32],
    rotation: LocalErasureSignerRotationV1,
    revoked: &[String],
) -> Result<(), LocalErasureRotationRefusalV1>
where
    S: ErasureInventoryPersistencePortV1 + ErasurePersistencePortV1 + ?Sized,
{
    bundle_pins(store, revoked)
        .ok_or(LocalErasureRotationRefusalV1::Pinned)
        .and_then(|pins| match rotation {
            LocalErasureSignerRotationV1::Routine => pins
                .is_empty()
                .then_some(())
                .ok_or(LocalErasureRotationRefusalV1::Pinned),
            LocalErasureSignerRotationV1::Compromise => (revoked
                .contains(&local_erasure_signer_key_id_v1(&old))
                && pins.iter().all(|&(_, revoked)| revoked))
            .then_some(())
            .ok_or(LocalErasureRotationRefusalV1::NotRevoked),
        })
}

/// The bundle one request pins (ADR-136 §5, *What a pin is*): its active
/// attempt's, or, frozen before its first attempt, its obligation set's.
/// A request before freeze, or after an attempt with none active, pins
/// none.
fn pinned_trust<S>(
    store: &S,
    request: ErasureReferenceV1,
) -> Result<Option<ErasureReferenceV1>, pos_core::ErasureErrorV1>
where
    S: ErasurePersistencePortV1 + ?Sized,
{
    store.recorded_active_attempt(request).and_then(|active| {
        active.map_or_else(
            || {
                ErasurePersistencePortV1::attempt_index_count(store, request).and_then(|attempts| {
                    if attempts == 0 {
                        store.recorded_obligation_trust(request)
                    } else {
                        Ok(None)
                    }
                })
            },
            |attempt| Ok(Some(attempt.trust())),
        )
    })
}

/// Whether `trust` names a retained ELB1 whose root or signer the installed
/// TPS1 revokes (ADR-136 §5, *Compromise*).
fn pins_revoked_bundle<S>(store: &S, trust: ErasureReferenceV1, revoked: &[String]) -> bool
where
    S: ErasurePersistencePortV1 + ?Sized,
{
    ErasurePersistencePortV1::read_object(store, trust)
        .ok()
        .and_then(|bytes| LocalErasureBundleV1::from_canonical_cbor(&bytes).ok())
        .is_some_and(|pinned| {
            revoked
                .iter()
                .any(|key_id| *key_id == pinned.issued_by || *key_id == pinned.signer_key_id)
        })
}
