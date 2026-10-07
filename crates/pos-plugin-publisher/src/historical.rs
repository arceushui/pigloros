//! Retained historical verification of one Plugin release (ADR-061 revision 2).
//!
//! A release signed before its key was rotated or destroyed must stay
//! verifiable: the registry retains the public key forever. This module
//! reports three separate facts about one verified release closure and
//! conflates none of them:
//!
//! 1. [`ReleaseSignatureMathV1`]: whether field 26 is a valid signature by the
//!    registry's retained public key over the exact 32 raw release-digest
//!    bytes under the ADR-065 role preimage `(owner, role 3, epoch)`.
//! 2. [`SigningKeyStateV1`]: what the key registry says about that identity.
//! 3. [`CurrentAdmissionV1`]: always `NotEvaluated`. The verifier never
//!    consults trust policy, revocation, the release's validity interval, or
//!    a clock, so no report can be read as "installable".

use pos_core::{KeyIdentityV1, KeyRegistryStateV1, KeyRoleV1, Signature};
use pos_crypto::plugin_manifest::{
    decode_plugin_release_signature_claim_v1, PluginManifestErrorV1,
};
use pos_plugin_release::VerifiedReleaseBundleV1;

use crate::{digest_payload, signature_verifies};

/// The signature-math fact. It says nothing about admission.
///
/// The enum is deliberately closed (no `#[non_exhaustive]`): the product is
/// unreleased, so a later slice replaces it in place in a coordinated
/// breaking change.
///
/// A retained key that is not a usable curve point reports `Invalid`, the
/// same as a wrong signature; only an absent key is `Unverifiable`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseSignatureMathV1 {
    /// The signature verifies under the retained public key.
    Valid,
    /// The retained key is present and the signature does not verify under
    /// it for this release digest, owner, role 3 and epoch.
    Invalid,
    /// No retained public key exists for the claimed identity, so the
    /// signature can be neither confirmed nor refuted.
    Unverifiable,
}

/// The registry's current record of the claimed signing identity.
///
/// The enum is deliberately closed (no `#[non_exhaustive]`): the product is
/// unreleased, so a later slice replaces it in place in a coordinated
/// breaking change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningKeyStateV1 {
    /// The identity is the owner's active `PluginReleaseSigning` epoch.
    Active,
    /// The identity was registered and a later epoch superseded it, with its
    /// private material still held.
    Rotated,
    /// A destruction request is recorded but not yet completed.
    DestructionPending,
    /// The identity has an immutable destruction tombstone.
    Destroyed,
    /// The registry has no record of the identity.
    Unknown,
}

/// The current-admission fact. There is deliberately one value.
///
/// Historical verification never evaluates trust policy, revocation or the
/// validity interval, so the only honest report is that admission was not
/// evaluated. Only the installer's admission path may decide installability.
///
/// The enum is deliberately closed (no `#[non_exhaustive]`): wiring admission
/// (#573) adds a new type or variant in a coordinated breaking change, since
/// the product is unreleased and types are replaced in place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentAdmissionV1 {
    /// No trust policy, revocation state, interval or clock was consulted.
    NotEvaluated,
}

/// The three independent facts about one historical release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalReleaseVerificationV1 {
    identity: KeyIdentityV1,
    release_digest: [u8; 32],
    pmf1_digest: [u8; 32],
    signature: ReleaseSignatureMathV1,
    key_state: SigningKeyStateV1,
}

impl HistoricalReleaseVerificationV1 {
    /// The claimed signing identity: owner (field 21), role 3, epoch (field 26).
    #[must_use]
    pub const fn identity(&self) -> KeyIdentityV1 {
        self.identity
    }

    /// The signed field 27 release digest, from the closure's own PMF1.
    #[must_use]
    pub const fn release_digest(&self) -> [u8; 32] {
        self.release_digest
    }

    /// BLAKE3-256 of the complete PMF1 bytes that were verified.
    #[must_use]
    pub const fn pmf1_digest(&self) -> [u8; 32] {
        self.pmf1_digest
    }

    /// Fact 1: the signature math under the retained public key.
    #[must_use]
    pub const fn signature(&self) -> ReleaseSignatureMathV1 {
        self.signature
    }

    /// Fact 2: the registry state of the signing key at the claimed epoch.
    #[must_use]
    pub const fn key_state(&self) -> SigningKeyStateV1 {
        self.key_state
    }

    /// Fact 3: current admission, which is never evaluated here.
    #[must_use]
    pub const fn current_admission(&self) -> CurrentAdmissionV1 {
        CurrentAdmissionV1::NotEvaluated
    }
}

/// Verify one release closure against the registry's retained key material.
///
/// The closure is strictly decoded, bound and digest-checked again, and the
/// owner, epoch, signature and release digest come only from its own PMF1
/// bytes. The retained public key is the one the registry keeps for
/// `(owner, PluginReleaseSigning, epoch)`, including after rotation and
/// destruction. The signed payload is the exact 32 raw release-digest bytes
/// under the ADR-065 role-bound preimage. No trust policy, revocation record,
/// validity interval or clock is consulted, so the report carries
/// [`CurrentAdmissionV1::NotEvaluated`].
///
/// # Errors
/// Returns the strict decode, closure or digest failure of the closure; the
/// installer (#573) must treat it as fail-closed. A bad signature or an
/// absent key is a report, not an error.
pub fn verify_plugin_release_historical_v1(
    bundle: &VerifiedReleaseBundleV1,
    registry: &KeyRegistryStateV1,
) -> Result<HistoricalReleaseVerificationV1, PluginManifestErrorV1> {
    let claim = decode_plugin_release_signature_claim_v1(bundle)?;
    let identity = KeyIdentityV1::from_parts(
        claim.owner(),
        KeyRoleV1::PluginReleaseSigning,
        claim.epoch(),
    );
    let payload = digest_payload(&claim.release_digest());
    let signature = Signature::from_bytes(claim.signature());
    let math = registry
        .key_record(identity)
        .and_then(|record| record.public_verification_key)
        .map_or(ReleaseSignatureMathV1::Unverifiable, |key| {
            if signature_verifies(&key, identity, &payload, &signature) {
                ReleaseSignatureMathV1::Valid
            } else {
                ReleaseSignatureMathV1::Invalid
            }
        });
    Ok(HistoricalReleaseVerificationV1 {
        identity,
        release_digest: claim.release_digest(),
        pmf1_digest: claim.pmf1_digest(),
        signature: math,
        key_state: key_state(registry, identity),
    })
}

/// The registry's state of `identity`; destruction outranks everything.
fn key_state(registry: &KeyRegistryStateV1, identity: KeyIdentityV1) -> SigningKeyStateV1 {
    if registry.tombstone(identity).is_some() {
        SigningKeyStateV1::Destroyed
    } else if registry.key_record(identity).is_none() {
        SigningKeyStateV1::Unknown
    } else if registry
        .pending_destruction_requests()
        .any(|request| request.identity == identity)
    {
        SigningKeyStateV1::DestructionPending
    } else if registry
        .active_key(&identity.owner_id, identity.role)
        .is_some_and(|active| active.identity == identity)
    {
        SigningKeyStateV1::Active
    } else {
        SigningKeyStateV1::Rotated
    }
}
