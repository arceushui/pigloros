use crate::{CanonicalBytes, Hash};

pub trait Hasher: Send + Sync {
    fn genesis_hash(&self) -> Hash;
    /// Compute the hash of a canonical payload (for `Event.payload_hash`).
    fn hash_payload(&self, payload: &CanonicalBytes) -> Hash;
    /// Compute the chain hash covering `previous_hash || event_id_bytes || payload_bytes`.
    fn hash_event(
        &self,
        previous_hash: &Hash,
        event_id_bytes: &[u8],
        payload: &CanonicalBytes,
    ) -> Hash;
}
