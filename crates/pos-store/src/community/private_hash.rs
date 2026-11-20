//! Owner-private BLAKE3 commitments over borrowed staging.
//!
//! The portable codecs intentionally have no digest for personal records.
//! Here the hasher and its final output reader are both zeroizing, and the
//! preimage is fed as borrowed slices of zeroizing staging plus fixed stack
//! scratch: no intermediate concatenation buffer is allocated. Stack scratch
//! inside the hash implementation is not wiped and is not claimed to be.
//! The returned 32-byte digest is itself a plain stack value: it is the
//! owner commitment that is stored beside the ciphertext, not a secret, so it
//! is deliberately not wiped.
//!
//! Items are `pub(super)`: the narrowest visibility that serves the sealed
//! `community` module. (`pub(crate)` here would only widen it, and Clippy's
//! `redundant_pub_crate` refuses it inside this private module.)

use pos_core::community_lifecycle::CommunityArtifactKindV1;
use pos_core::Hash;
use zeroize::Zeroizing;

/// `BLAKE3(domain || 0x00 || parts...)` with wiped hasher and output state.
pub(super) fn private_digest(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    hasher.update(domain);
    hasher.update(&[0]);
    for part in parts {
        hasher.update(part);
    }
    let mut output = Zeroizing::new(hasher.finalize_xof());
    let mut digest = [0; 32];
    output.fill(&mut digest);
    Hash::from_bytes(digest)
}

/// ADR-128 private owner commitment of one exact plaintext record.
pub(super) fn plaintext_commitment(kind: CommunityArtifactKindV1, plaintext: &[u8]) -> Hash {
    private_digest(
        b"PiglorOS.Community.OwnerPlaintext.v1",
        &[
            &kind.code().to_be_bytes(),
            &(plaintext.len() as u64).to_be_bytes(),
            plaintext,
        ],
    )
}

/// ADR-129 `ScopeSet` digest over the preferred array of exact scope rows.
pub(super) fn scope_set_digest(canonical_rows: &[u8]) -> Hash {
    private_digest(b"PiglorOS.Community.ScopeSet.v1", &[canonical_rows])
}
