//! The sign, assemble, self-check, publish sequence.

use pos_core::{
    KeyIdentityV1, KeyRegistryErrorV1, KeyRegistrySigningPortV1, KeyRoleV1, PublicKey, Signature,
};
use pos_crypto::key_roles::{sign_for_registered_role, SigningKeyMaterial};
use pos_crypto::plugin_manifest::{
    PluginManifestErrorV1, PluginReleaseDraftV1, UnsignedPluginReleaseV1,
};
use pos_crypto::plugin_trust::ValidatedPluginManifestProjectionV1;
use pos_plugin_release::{
    build_oci_closure_v1, BundleAddressV1, LocalOciPublicationErrorV1, LocalOciPublisherV1,
    PublishOutcomeV1, ReleaseClosureInputV1, ReleaseSourceErrorV1, VerifiedReleaseBundleV1,
};
use thiserror::Error;

use crate::{digest_payload, signature_verifies};

/// A closed failure of Plugin release publication.
///
/// Every variant means no release became discoverable through the store's
/// committed index, except [`LocalOciPublicationErrorV1::OutcomeUnknown`]
/// inside `Publication`: the caller must then call
/// [`LocalOciPublisherV1::recover()`] for its address.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PluginReleasePublishErrorV1 {
    /// The draft is not a valid PMF1, or the assembled PMF1 failed the
    /// strict decoder.
    #[error(transparent)]
    Manifest(#[from] PluginManifestErrorV1),
    /// The registry refused the signing identity: absent, inactive, stale,
    /// pending or destroyed, or the key does not match its registration.
    #[error(transparent)]
    Authorization(#[from] KeyRegistryErrorV1),
    /// The signature does not verify under the supplied public key for the
    /// draft's owner, role 3, epoch and release digest.
    #[error("release signature does not verify")]
    InvalidSignature,
    /// The OCI closure could not be built.
    #[error(transparent)]
    Closure(#[from] ReleaseSourceErrorV1),
    /// The local OCI store refused or could not complete publication.
    #[error(transparent)]
    Publication(#[from] LocalOciPublicationErrorV1),
}

/// One release that reached the store's committed index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedPluginReleaseV1 {
    outcome: PublishOutcomeV1,
    identity: KeyIdentityV1,
    release_digest: [u8; 32],
}

impl PublishedPluginReleaseV1 {
    /// Whether this call committed the release or an equivalent one already
    /// existed.
    #[must_use]
    pub const fn outcome(&self) -> &PublishOutcomeV1 {
        &self.outcome
    }

    /// The immutable OCI address of the committed release.
    #[must_use]
    pub const fn address(&self) -> &BundleAddressV1 {
        match &self.outcome {
            PublishOutcomeV1::Published(address) | PublishOutcomeV1::AlreadyPublished(address) => {
                address
            }
        }
    }

    /// The signing identity: publisher owner, `PluginReleaseSigning`, epoch.
    #[must_use]
    pub const fn identity(&self) -> KeyIdentityV1 {
        self.identity
    }

    /// The signed field 27 release digest.
    #[must_use]
    pub const fn release_digest(&self) -> [u8; 32] {
        self.release_digest
    }
}

/// A release signature: the signing epoch and the Ed25519 signature bytes
/// over the ADR-065 message for the draft's release digest.
///
/// It carries no key and no authority. [`publish_signed_plugin_release_v1()`]
/// verifies it under an explicit public key before anything is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginReleaseSignatureV1 {
    epoch: u64,
    signature: Signature,
}

impl PluginReleaseSignatureV1 {
    /// Wrap a retained signature and the epoch it was made under.
    #[must_use]
    pub const fn new(epoch: u64, signature: [u8; 64]) -> Self {
        Self {
            epoch,
            signature: Signature::from_bytes(signature),
        }
    }

    /// The signing key epoch (PMF1 field 26).
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The 64 signature bytes (PMF1 field 26).
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        self.signature.as_bytes()
    }
}

/// Sign one release draft under the registry.
///
/// The draft carries the explicit validity interval; no clock is read. The
/// draft is encoded and its artifacts are proved to form a closure the strict
/// decoder accepts (with a placeholder signature), so a draft that cannot be
/// published is never signed. The signed payload is exactly the 32 raw bytes
/// of the field 27 release digest, signed as `(draft owner,
/// PluginReleaseSigning, epoch)` through the registry's atomic signing
/// authorization with the ADR-065 role-bound preimage. Nothing is stored.
///
/// This function does not verify its own output. Callers must publish through
/// [`publish_plugin_release_v1()`] or [`publish_signed_plugin_release_v1()`],
/// which verify the signature first.
///
/// # Errors
/// Returns `Manifest` for an invalid draft or epoch zero, `Closure` when the
/// artifacts cannot form a closure, and `Authorization` when the registry
/// refuses `(owner, role 3, epoch)` (absent, inactive, stale, pending,
/// destroyed) or the key material does not match the registration.
pub fn sign_plugin_release_v1<R: KeyRegistrySigningPortV1>(
    registry: &mut R,
    signing_key: &SigningKeyMaterial,
    epoch: u64,
    draft: &PluginReleaseDraftV1<'_>,
) -> Result<PluginReleaseSignatureV1, PluginReleasePublishErrorV1> {
    let unsigned = draft.unsigned()?;
    // This placeholder assembly copies every artifact once more; that cost is
    // deliberate, because it is what guarantees an unpublishable draft is never
    // signed. The composite path therefore assembles twice (pre-sign, final).
    assemble(draft, &unsigned.with_signature(epoch, [0; 64])?)?;
    let identity = signing_identity(&unsigned, epoch);
    let payload = digest_payload(&unsigned.release_digest());
    let signature = sign_for_registered_role(registry, signing_key, identity, &payload)?;
    Ok(PluginReleaseSignatureV1 { epoch, signature })
}

/// Publish one release whose signature was already made.
///
/// The signature must verify under `public_key` over the ADR-065 message for
/// the draft's owner, role 3, `signature.epoch()` and release digest. The
/// registry is not consulted: a valid signature made before the signing key
/// was destroyed may be published afterwards, using the public key the
/// registry retains after destruction. Trust policy, not publication, decides
/// whether such a release is ever installed (ADR-061 revision 2).
///
/// The final PMF1 and OCI closure are assembled and decoded again with the
/// strict decoder before the store sees them. A failure at any step publishes
/// nothing: nothing is stored before `publish`, and the store makes a release
/// discoverable only at its durable index transition.
///
/// # Errors
/// Returns `Manifest` for an invalid draft or epoch zero, `InvalidSignature` when the
/// signature or key does not verify, `Closure` when the artifacts cannot form
/// a closure, and `Publication` for a store failure, which may be
/// `OutcomeUnknown(address)`.
pub fn publish_signed_plugin_release_v1(
    draft: &PluginReleaseDraftV1<'_>,
    signature: &PluginReleaseSignatureV1,
    public_key: &PublicKey,
    store: &LocalOciPublisherV1,
) -> Result<PublishedPluginReleaseV1, PluginReleasePublishErrorV1> {
    let unsigned = draft.unsigned()?;
    let identity = signing_identity(&unsigned, signature.epoch);
    let release_digest = unsigned.release_digest();
    let pmf1 = unsigned.with_signature(signature.epoch, *signature.signature())?;
    let payload = digest_payload(&release_digest);
    if !signature_verifies(public_key, identity, &payload, &signature.signature) {
        return Err(PluginReleasePublishErrorV1::InvalidSignature);
    }
    let bundle = assemble(draft, &pmf1)?;
    let outcome = store.publish(&bundle)?;
    Ok(PublishedPluginReleaseV1 {
        outcome,
        identity,
        release_digest,
    })
}

/// Sign `draft` under the registry and publish it to `store`.
///
/// This is [`sign_plugin_release_v1()`] followed by
/// [`publish_signed_plugin_release_v1()`] under the signing key's own public
/// key, so the signature is verified before publication.
///
/// # Errors
/// Returns the first error of either step.
pub fn publish_plugin_release_v1<R: KeyRegistrySigningPortV1>(
    registry: &mut R,
    signing_key: &SigningKeyMaterial,
    epoch: u64,
    draft: &PluginReleaseDraftV1<'_>,
    store: &LocalOciPublisherV1,
) -> Result<PublishedPluginReleaseV1, PluginReleasePublishErrorV1> {
    let signature = sign_plugin_release_v1(registry, signing_key, epoch, draft)?;
    let public_key = signing_key.public_verification_key();
    publish_signed_plugin_release_v1(draft, &signature, &public_key, store)
}

/// `(draft owner, PluginReleaseSigning, epoch)`.
const fn signing_identity(unsigned: &UnsignedPluginReleaseV1, epoch: u64) -> KeyIdentityV1 {
    KeyIdentityV1::from_parts(unsigned.owner(), KeyRoleV1::PluginReleaseSigning, epoch)
}

/// Build the closure of `pmf1` and the draft's artifacts, then decode it
/// strictly so the draft, its descriptors and the closure agree.
fn assemble(
    draft: &PluginReleaseDraftV1<'_>,
    pmf1: &[u8],
) -> Result<VerifiedReleaseBundleV1, PluginReleasePublishErrorV1> {
    let mut schemas = draft
        .event_schemas
        .iter()
        .map(|schema| schema.artifact.bytes)
        .collect::<Vec<_>>();
    schemas.push(draft.state_schema.artifact.bytes);
    schemas.extend(
        draft
            .configuration_schema
            .iter()
            .map(|schema| schema.artifact.bytes),
    );
    let bundle = build_oci_closure_v1(&ReleaseClosureInputV1 {
        pmf1,
        component: draft.component.bytes,
        wit: draft.wit.bytes,
        schemas,
        provenance: draft.provenance.bytes,
        sbom: draft.sbom.bytes,
        licences: draft.licences.iter().map(|item| item.bytes).collect(),
        // PMF1 V1 field 16 must be empty, so a V1 release has no migration fixtures.
        migration_fixtures: Vec::new(),
    })?;
    ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle).map(drop)?;
    Ok(bundle)
}
