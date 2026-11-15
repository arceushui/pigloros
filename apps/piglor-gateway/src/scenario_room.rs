//! The Scenario Room resources of Gateway v1 (#1398, parent #303).

use pos_core::{EventId, Hash};

/// The domain of a revision's provenance digest: this prefix, the 32
/// `descriptor_hash` bytes and the 16 big-endian bytes of the committed
/// `EventId`.
const PROVENANCE_DOMAIN: &[u8] = b"PiglorOS.GatewayScenarioRoomRevision.v1\0";

/// The `provenance.digest` of one `ScenarioRoomRevision`: BLAKE3 of
/// [`PROVENANCE_DOMAIN`], the revision's `descriptor_hash` and the 16 bytes
/// of the `EventId` that committed it, in lower-case hex.
#[must_use]
pub fn revision_provenance_digest_v1(descriptor_hash: &Hash, event_id: EventId) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROVENANCE_DOMAIN);
    hasher.update(descriptor_hash.as_bytes());
    hasher.update(&event_id.inner().to_bytes());
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
