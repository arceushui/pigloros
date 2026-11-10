//! Borrowed CSC1 plaintext view; retained bytes must use the protected owner.

use super::{
    bounded_bytes, canonical_end, fixed_bytes, record_cursor, record_prefix,
    CommunityLifecycleErrorV1, Result,
};
use crate::{encode_head, Hash};
use zeroize::Zeroizing;

/// Maximum opaque Plugin State bytes in the accepted CSC1 schema.
pub const MAX_COMMUNITY_STATE_BYTES_V1: usize = 1_048_576;
const MAX_RECORD_BYTES: usize = 1_048_624;

/// A structurally valid CSC1 view borrowing caller-owned plaintext.
///
/// Decoding borrows the state payload and allocates only bounded framing
/// buffers. This view is not a protected owner, authorization, retained
/// artifact or live-state restoration capability.
/// It deliberately has no Debug/Serialize implementation that could reveal
/// state or create another persistence encoding.
/// Plaintext hashing belongs to the qualified protected owner, which must
/// account for the cryptographic implementation's temporary copies.
///
/// The portable view cannot hash private State outside that owner:
///
/// ```compile_fail,E0599
/// use pos_core::community_lifecycle::CommunityStateContentV1;
/// fn hash_without_owner(state: &CommunityStateContentV1<'_>) {
///     let _ = state.digest();
/// }
/// ```
pub struct CommunityStateContentV1<'a> {
    schema: Hash,
    state: &'a [u8],
}

impl<'a> CommunityStateContentV1<'a> {
    /// Check the required schema address and exact opaque state bound.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero schema or `BoundsExceeded` when the
    /// state exceeds one MiB. Empty state is valid and is not missing evidence.
    pub fn new(schema: Hash, state: &'a [u8]) -> Result<Self> {
        if schema == Hash::zero() {
            return Err(CommunityLifecycleErrorV1::InvalidBinding);
        }
        if state.len() > MAX_COMMUNITY_STATE_BYTES_V1 {
            return Err(CommunityLifecycleErrorV1::BoundsExceeded);
        }
        Ok(Self { schema, state })
    }

    /// Return the admitted state-schema identity, without authenticating it.
    #[must_use]
    pub const fn schema_digest(&self) -> Hash {
        self.schema
    }

    /// Borrow the plaintext supplied by this view's caller.
    #[must_use]
    pub const fn state_bytes(&self) -> &'a [u8] {
        self.state
    }

    /// Encode into an owned zeroizing buffer; the host still inventories copies.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        // Validation bounds the payload to one MiB. The accepted 48-byte
        // framing allowance covers every preferred header, so no growth can
        // leave a previous prefix allocation outside the zeroizing owner.
        let mut out = Zeroizing::new(Vec::with_capacity(self.state.len() + 48));
        record_prefix(&mut out, 4, *b"CSC1");
        crate::encode_hash(&mut out, self.schema);
        encode_head(&mut out, 2, self.state.len() as u64);
        out.extend_from_slice(self.state);
        out
    }

    /// Decode a complete preferred CSC1, borrowing its exact state byte range.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing bytes, unsupported versions,
    /// zero schema identity and oversized records or state lengths.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_RECORD_BYTES, 4, *b"CSC1").and_then(|mut cursor| {
            fixed_bytes(&mut cursor).and_then(|schema| {
                bounded_bytes(&mut cursor, MAX_COMMUNITY_STATE_BYTES_V1)
                    .and_then(|state| Self::new(Hash::from_bytes(schema), state))
                    .and_then(|record| canonical_end(&cursor).map(|()| record))
            })
        })
    }
}
