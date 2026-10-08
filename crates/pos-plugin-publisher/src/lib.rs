#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! Registry-authorized Plugin release publication (ADR-061 revision 2).
//!
//! The publisher turns one typed release draft with an explicit validity
//! interval into a signed, self-verified OCI release in a Linux-local ADR-102
//! store. It reads no ambient clock. Local OCI publication is Linux-only, so
//! the whole crate is empty on other targets.
//!
//! Retained historical verification reports signature math, the registry
//! state of the signing key, and an explicit "current admission not
//! evaluated" as three separate facts. Neither publication nor historical
//! verification ever admits or installs a release.
//!
//! The signed installer (#573) reads one verified release, authorizes it with
//! trust evidence, verifies its PMF1 signature, and only then asks the Plugin
//! trust policy registry to admit it. It does not validate artifact content
//! (follow-up #574) and builds no activation Event (the caller supplies it).

#[cfg(target_os = "linux")]
use pos_core::{CanonicalBytes, KeyIdentityV1, PublicKey, Signature};
#[cfg(target_os = "linux")]
use pos_crypto::key_roles::verify_for_role;
#[cfg(target_os = "linux")]
use pos_crypto::signing::verifying_key_from_public_key;

#[cfg(target_os = "linux")]
mod historical;
#[cfg(target_os = "linux")]
mod install;
#[cfg(target_os = "linux")]
mod publish;

#[cfg(target_os = "linux")]
pub use historical::{
    verify_plugin_release_historical_v1, CurrentAdmissionV1, HistoricalReleaseVerificationV1,
    ReleaseSignatureMathV1, SigningKeyStateV1,
};

#[cfg(target_os = "linux")]
pub use install::{
    install_plugin_release_v1, ContentValidationV1, InstalledPluginReleaseV1,
    PluginInstallRequestV1, PluginReleaseInstallErrorV1,
};

#[cfg(target_os = "linux")]
pub use publish::{
    publish_plugin_release_v1, publish_signed_plugin_release_v1, sign_plugin_release_v1,
    PluginReleasePublishErrorV1, PluginReleaseSignatureV1, PublishedPluginReleaseV1,
};

// These two helpers are shared by the `historical` and `publish` modules, so
// they live at the crate root: in a private module `pub(crate)` trips
// `clippy::redundant_pub_crate` and `pub` trips `unreachable_pub`.

/// The exact 32 raw bytes of a release digest, the signed payload.
#[cfg(target_os = "linux")]
pub(crate) fn digest_payload(digest: &[u8; 32]) -> CanonicalBytes {
    CanonicalBytes::from_vec(digest.to_vec())
}

/// Whether `signature` is a valid role-bound signature by `public_key`; a key
/// that is not a curve point fails the same way a wrong signature does (pinned
/// by a test).
#[cfg(target_os = "linux")]
pub(crate) fn signature_verifies(
    public_key: &PublicKey,
    identity: KeyIdentityV1,
    payload: &CanonicalBytes,
    signature: &Signature,
) -> bool {
    verifying_key_from_public_key(public_key)
        .is_ok_and(|key| verify_for_role(&key, identity, payload, signature).is_ok())
}
