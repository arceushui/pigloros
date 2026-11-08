//! Borrowed CSC1 plaintext view; retained bytes must use the protected owner.

use super::{fixed_bytes, record_cursor, record_prefix, CommunityLifecycleErrorV1, Result};
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
        let mut out = Zeroizing::new(self.prefix());
        out.extend_from_slice(self.state);
        out
    }

    /// Hash the exact CSC1 encoding without copying the state plaintext.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.Community.CSC1.v1\0");
        hasher.update(&self.prefix());
        hasher.update(self.state);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Decode a complete preferred CSC1, borrowing its exact state byte range.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing bytes, unsupported versions,
    /// zero schema identity and oversized records or state lengths.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_RECORD_BYTES, 4, b"CSC1").and_then(|mut cursor| {
            fixed_bytes(&mut cursor).and_then(|schema| {
                cursor
                    .head(2)
                    .map_err(CommunityLifecycleErrorV1::from)
                    .and_then(|length| {
                        // Saturation is always above the admitted MiB bound,
                        // including an unrepresentable wire length on wasm32.
                        let length = usize::try_from(length).unwrap_or(usize::MAX);
                        if length > MAX_COMMUNITY_STATE_BYTES_V1 {
                            return Err(CommunityLifecycleErrorV1::BoundsExceeded);
                        }
                        cursor.take(length).map_err(CommunityLifecycleErrorV1::from)
                    })
                    .and_then(|state| Self::new(Hash::from_bytes(schema), state))
                    .and_then(|record| {
                        if cursor.is_finished() && bytes.starts_with(&record.prefix()) {
                            Ok(record)
                        } else {
                            Err(CommunityLifecycleErrorV1::InvalidEncoding)
                        }
                    })
            })
        })
    }

    fn prefix(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        record_prefix(&mut out, 4, b"CSC1");
        crate::encode_hash(&mut out, self.schema);
        encode_head(&mut out, 2, self.state.len() as u64);
        out
    }
}
