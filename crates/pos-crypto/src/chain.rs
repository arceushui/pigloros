//! BLAKE3-256 tamper-evident hash chain.
//!
//! Each event's hash covers: `previous_hash` || `event_id` || `payload_bytes`
//! A tampered payload causes its hash to differ, which then invalidates all subsequent hashes.

use blake3::Hasher;
use pos_core::{CanonicalBytes, Hash};

/// Compute the BLAKE3 hash for a single event's entry in the chain.
///
/// Input: `previous_hash || event_id_bytes || payload_bytes`
pub fn hash_event(
    previous_hash: &Hash,
    event_id_bytes: &[u8],
    payload: &CanonicalBytes,
) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(previous_hash.as_bytes());
    hasher.update(event_id_bytes);
    hasher.update(payload.as_slice());
    let result = hasher.finalize();
    Hash::from_bytes(*result.as_bytes())
}

/// Compute the hash of just a payload (for `Event.payload_hash`).
pub fn hash_payload(payload: &CanonicalBytes) -> Hash {
    let result = blake3::hash(payload.as_slice());
    Hash::from_bytes(*result.as_bytes())
}

/// Verify a chain of (`previous_hash`, `event_id_bytes`, payload) tuples.
///
/// Returns `Ok(final_hash)` if the chain is intact.
///
/// # Errors
/// Returns `Err(broken_index)` if the computed hash at `broken_index` does not match the stored hash.
pub fn verify_chain<'a>(
    genesis_hash: &Hash,
    entries: impl Iterator<Item = (&'a [u8], &'a CanonicalBytes, &'a Hash)>,
) -> Result<Hash, usize> {
    let mut prev = *genesis_hash;
    for (i, (event_id_bytes, payload, expected_hash)) in entries.enumerate() {
        let computed = hash_event(&prev, event_id_bytes, payload);
        if &computed != expected_hash {
            return Err(i);
        }
        prev = computed;
    }
    Ok(prev)
}

/// An all-zeros genesis hash for the start of a new timeline.
#[must_use] 
pub const fn genesis_hash() -> Hash {
    Hash::zero()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(b: &[u8]) -> CanonicalBytes {
        CanonicalBytes::from_vec(b.to_vec())
    }

    fn id(b: u8) -> Vec<u8> {
        vec![b; 16]
    }

    #[test]
    fn hash_event_is_deterministic() {
        let prev = genesis_hash();
        let eid = id(1);
        let p = payload(b"hello");
        let h1 = hash_event(&prev, &eid, &p);
        let h2 = hash_event(&prev, &eid, &p);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_payloads_produce_different_hashes() {
        let prev = genesis_hash();
        let eid = id(1);
        let h1 = hash_event(&prev, &eid, &payload(b"a"));
        let h2 = hash_event(&prev, &eid, &payload(b"b"));
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_event_ids_produce_different_hashes() {
        let prev = genesis_hash();
        let p = payload(b"same");
        let h1 = hash_event(&prev, &id(1), &p);
        let h2 = hash_event(&prev, &id(2), &p);
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_previous_hashes_produce_different_hashes() {
        let prev1 = Hash::from_bytes([1u8; 32]);
        let prev2 = Hash::from_bytes([2u8; 32]);
        let eid = id(1);
        let p = payload(b"same");
        let h1 = hash_event(&prev1, &eid, &p);
        let h2 = hash_event(&prev2, &eid, &p);
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_chain_accepts_intact_chain() {
        let g = genesis_hash();
        let eid1 = id(1);
        let eid2 = id(2);
        let p1 = payload(b"event1");
        let p2 = payload(b"event2");

        let h1 = hash_event(&g, &eid1, &p1);
        let h2 = hash_event(&h1, &eid2, &p2);

        let entries: Vec<(&[u8], &CanonicalBytes, &Hash)> = vec![
            (&eid1, &p1, &h1),
            (&eid2, &p2, &h2),
        ];
        let result = verify_chain(&g, entries.into_iter());
        assert_eq!(result, Ok(h2));
    }

    #[test]
    fn verify_chain_detects_tampered_payload() {
        let g = genesis_hash();
        let eid1 = id(1);
        let eid2 = id(2);
        let p1 = payload(b"event1");
        let p2 = payload(b"event2");

        let h1 = hash_event(&g, &eid1, &p1);
        let h2 = hash_event(&h1, &eid2, &p2);

        // Tamper: change p1 after the hash was computed
        let p1_tampered = payload(b"TAMPERED");
        let entries: Vec<(&[u8], &CanonicalBytes, &Hash)> = vec![
            (&eid1, &p1_tampered, &h1), // hash is stale — won't match tampered payload
            (&eid2, &p2, &h2),
        ];
        let result = verify_chain(&g, entries.into_iter());
        assert_eq!(result, Err(0)); // broken at index 0
    }

    #[test]
    fn verify_chain_detects_tampered_middle_event() {
        let g = genesis_hash();
        let eids: Vec<Vec<u8>> = (0..4u8).map(id).collect();
        let payloads: Vec<CanonicalBytes> = (0..4u8).map(|i| payload(&[i])).collect();

        let mut hashes = vec![g];
        for i in 0..4 {
            let h = hash_event(&hashes[i], &eids[i], &payloads[i]);
            hashes.push(h);
        }

        // Tamper event at index 2
        let tampered = payload(b"bad");
        let entries: Vec<(&[u8], &CanonicalBytes, &Hash)> = vec![
            (&eids[0], &payloads[0], &hashes[1]),
            (&eids[1], &payloads[1], &hashes[2]),
            (&eids[2], &tampered, &hashes[3]),  // tampered payload, stale hash
            (&eids[3], &payloads[3], &hashes[4]),
        ];
        let result = verify_chain(&g, entries.into_iter());
        assert_eq!(result, Err(2));
    }

    #[test]
    fn verify_empty_chain_returns_genesis() {
        let g = genesis_hash();
        let result = verify_chain(&g, std::iter::empty());
        assert_eq!(result, Ok(g));
    }

    #[test]
    fn hash_payload_is_deterministic() {
        let p = payload(b"test data");
        assert_eq!(hash_payload(&p), hash_payload(&p));
    }

    #[test]
    fn hash_payload_differs_for_different_payloads() {
        assert_ne!(hash_payload(&payload(b"a")), hash_payload(&payload(b"b")));
    }

    proptest::proptest! {
        #[test]
        fn hash_event_is_sensitive_to_payload_changes(data: Vec<u8>, extra: u8) {
            let prev = genesis_hash();
            let eid = id(1);
            let p1 = payload(&data);
            let mut modified = data;
            modified.push(extra);
            // Only skip if extra makes them identical (same content)
            let p2 = payload(&modified);
            if p1.as_slice() != p2.as_slice() {
                assert_ne!(hash_event(&prev, &eid, &p1), hash_event(&prev, &eid, &p2));
            }
        }
    }
}
