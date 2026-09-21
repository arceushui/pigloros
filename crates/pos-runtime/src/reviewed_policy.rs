//! Host-owned identity helpers for the reviewed output-policy artifacts.
//!
//! Registration callers provide the concrete implementation artifact and the
//! canonical configuration details for the Plugin instance.  This module
//! supplies the stable framing used for configuration identity and the
//! accepted RTP1 retention-policy artifact; it does not create a default
//! admission policy or grant authority.

use pos_core::{Hash, Plugin};

/// Maximum bytes accepted for an installed implementation artifact.
///
/// Implementation artifacts are retained as opaque host-owned leaves in this
/// bounded admission slice.  They are deliberately capped before any copy is
/// made; the bound is large enough for the installed source artifacts used by
/// the composition roots while preventing an unbounded blob from entering a
/// replay closure.
pub const MAX_PLUGIN_IMPLEMENTATION_ARTIFACT_BYTES_V1: usize = 1_048_576;

/// Maximum bytes accepted for one canonical CFG1 configuration artifact.
pub const MAX_PLUGIN_CONFIGURATION_ARTIFACT_BYTES_V1: usize = 1_048_576;

/// Maximum bytes accepted for the caller-provided configuration details
/// before CFG1 framing allocates its output buffer.
pub const MAX_PLUGIN_CONFIGURATION_DETAILS_BYTES_V1: usize =
    MAX_PLUGIN_CONFIGURATION_ARTIFACT_BYTES_V1;

/// Closed errors for host-owned reviewed policy artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReviewedPolicyArtifactErrorV1 {
    #[error("implementation artifact exceeds its V1 bound")]
    ImplementationArtifactTooLarge,
    #[error("configuration details exceed their V1 bound")]
    ConfigurationDetailsTooLarge,
    #[error("configuration artifact exceeds its V1 bound")]
    ConfigurationArtifactTooLarge,
}

/// Canonical RTP1 policy artifact for the accepted initial World Replay
/// purpose.  The audience-policy leaf is the accepted ADR-076 Revision 2
/// identity, and the temporal values are the accepted 90/30/120-day policy.
const REVIEWED_RETENTION_POLICY_RTP1: &[u8] = &[
    0x8a, 0x44, b'R', b'T', b'P', b'1', 0x01, 0x01, 0x6f, b'w', b'o', b'r', b'l', b'd', b'-', b'r',
    b'e', b'p', b'l', b'a', b'y', b'-', b'v', b'1', 0x58, 0x20, 0xb8, 0x99, 0x9e, 0x89, 0x30, 0x5c,
    0x44, 0xdd, 0xa7, 0x5e, 0x99, 0x90, 0x82, 0xb9, 0xa0, 0x16, 0xb6, 0x3f, 0x86, 0xf4, 0x7f, 0x28,
    0xdd, 0x1a, 0x25, 0x43, 0x7a, 0x70, 0xdd, 0x7e, 0xd2, 0x76, 0x18, 0x5a, 0x18, 0x1e, 0x18, 0x78,
    0x00, 0x00,
];

/// Return the exact canonical RTP1 bytes used by the host composition root.
///
/// The caller must retain these bytes as part of the replay closure.  A digest
/// alone is not sufficient evidence that the policy artifact can be retrieved
/// and independently verified during Replay.
#[must_use]
pub const fn reviewed_retention_policy_bytes_v1() -> &'static [u8] {
    REVIEWED_RETENTION_POLICY_RTP1
}

/// Hash one host-recorded artifact with its explicit identity domain.
#[must_use]
pub fn host_artifact_hash_v1(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Hash a concrete implementation artifact with the project identity domain.
#[must_use]
pub fn implementation_artifact_hash_v1(bytes: &[u8]) -> Hash {
    host_artifact_hash_v1(b"pigloros.implementation-artifact.v1", bytes)
}

/// Hash an exact executable-profile artifact by its recorded BLAKE3 member
/// identity.  EPF1 profiles are independently materialized by the conformance
/// authority and are passed in by the composition root.
#[must_use]
pub fn execution_profile_artifact_hash_v1(bytes: &[u8]) -> Hash {
    Hash::from_bytes(*blake3::hash(bytes).as_bytes())
}

/// Hash the accepted canonical RTP1 retention policy artifact.
#[must_use]
pub fn reviewed_retention_policy_hash_v1() -> Hash {
    host_artifact_hash_v1(
        b"pigloros.retention-policy.v1",
        REVIEWED_RETENTION_POLICY_RTP1,
    )
}

/// Build the canonical base-configuration artifact for one Plugin instance.
///
/// The Plugin ID is deliberately excluded because it is an allocated runtime
/// address.  Name, version, owned namespaces and the caller's canonical
/// configuration bytes identify the implementation configuration without
/// making replay identity depend on a fresh ULID.
#[must_use]
pub fn canonical_plugin_configuration_v1(
    plugin: &dyn Plugin,
    details: &[u8],
) -> Result<Vec<u8>, ReviewedPolicyArtifactErrorV1> {
    if details.len() > MAX_PLUGIN_CONFIGURATION_DETAILS_BYTES_V1 {
        return Err(ReviewedPolicyArtifactErrorV1::ConfigurationDetailsTooLarge);
    }
    let mut artifact = Vec::new();
    artifact.extend_from_slice(b"CFG1");
    frame(&mut artifact, plugin.name().as_bytes());
    frame(&mut artifact, plugin.version().as_bytes());
    let mut capability = plugin
        .capability()
        .owned_event_types
        .into_iter()
        .map(|kind| kind.as_str().to_owned())
        .collect::<Vec<_>>();
    capability.sort_unstable();
    for event_type in capability {
        frame(&mut artifact, event_type.as_bytes());
    }
    frame(&mut artifact, details);
    if artifact.len() > MAX_PLUGIN_CONFIGURATION_ARTIFACT_BYTES_V1 {
        return Err(ReviewedPolicyArtifactErrorV1::ConfigurationArtifactTooLarge);
    }
    Ok(artifact)
}

fn frame(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}
