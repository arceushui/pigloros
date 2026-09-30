//! Shared framing and digest helpers for the ADR-101 adapter byte codecs.

use crate::Hash;

pub(crate) fn length_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

pub(crate) fn hash_bytes(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

pub(crate) fn encode_hash(out: &mut Vec<u8>, hash: Hash) {
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(hash.as_bytes());
}

pub(crate) fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8], major: u8) {
    crate::encode_head(out, major, bytes.len() as u64);
    out.extend_from_slice(bytes);
}
