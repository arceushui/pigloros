//! Immutable CMB1 binding; member data is never installed release authority.

use super::{
    bounded_text, canonical_end, digest, encode_implementation_key, read_hashes,
    read_implementation_key, record_cursor, record_prefix, CommunityLifecycleErrorV1 as Error,
    Result,
};
use crate::{encode_bytes, encode_hash, Hash, ImplementationKeyV1};
use zeroize::Zeroizing;

const _: () = assert!(7 + 66 + 3 + crate::MAX_IMPLEMENTATION_KEY_BYTES_V1 + 5 * 34 <= 1024);

/// Untrusted immutable member fields, including the exact retained IMK1.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityMemberBindingInputV1<'a> {
    /// Original ADR-088 stable entry, not a run-local Plugin ID.
    pub stable_entry: &'a str,
    /// Exact implementation Plugin ID, host version and release identity.
    pub implementation: &'a ImplementationKeyV1,
    /// Complete admitted PMF1 identity.
    pub pmf1_digest: Hash,
    /// Exact release State schema.
    pub state_schema_digest: Hash,
    /// Complete CNT1 identity, including mode and all effective limits.
    pub negotiated_tuple_digest: Hash,
    /// Actual admitted initializer CSC1 identity, including empty State.
    pub initial_state_content_digest: Hash,
    /// Exact COB1 binding; a historical hash does not grant current use.
    pub protected_owner_binding_digest: Hash,
}

/// Borrowed nine-field CMB1, immutable for one admitted generation.
///
/// A release/profile/schema/owner change requires an admitted generation
/// transition. This data view cannot register an implementation or perform one.
pub struct CommunityMemberBindingV1<'a>(CommunityMemberBindingInputV1<'a>);

impl<'a> CommunityMemberBindingV1<'a> {
    /// Check the stable entry and required nonzero identities.
    ///
    /// # Errors
    /// Rejects invalid ADR-088 entries or zero release/record links. The actual
    /// release schema/initializer, negotiated tuple and owner remain independent
    /// installed-composition checks; wire validity cannot establish them.
    pub fn new(input: CommunityMemberBindingInputV1<'a>) -> Result<Self> {
        if !crate::manifest_plugin_roster::valid_slot(input.stable_entry)
            || input.implementation.release_digest() == Hash::zero()
            || [
                input.pmf1_digest,
                input.state_schema_digest,
                input.negotiated_tuple_digest,
                input.initial_state_content_digest,
                input.protected_owner_binding_digest,
            ]
            .contains(&Hash::zero())
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(Self(input))
        }
    }

    /// Borrow exact historical fields without cloning the retained IMK1 texts.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityMemberBindingInputV1<'a> {
        &self.0
    }

    /// Copy fields into a pre-sized zeroizing buffer, preserving exact IMK1.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 9, *b"CMB1");
        encode_bytes(&mut out, input.stable_entry.as_bytes(), 3);
        encode_implementation_key(&mut out, input.implementation);
        for hash in [
            input.pmf1_digest,
            input.state_schema_digest,
            input.negotiated_tuple_digest,
            input.initial_state_content_digest,
            input.protected_owner_binding_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        out
    }

    /// Exact protected CMB1 logical identity, not a registry or authority token.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CMB1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode against the actual independently retained implementation key.
    ///
    /// # Errors
    /// Rejects unbounded/nonpreferred/malformed/trailing/versioned bytes,
    /// invalid entries/links or any nested IMK1 substitution. Decoding never
    /// reconstructs an unregistered implementation from attacker-owned text.
    pub fn from_canonical_cbor(
        bytes: &'a [u8],
        implementation: &'a ImplementationKeyV1,
    ) -> Result<Self> {
        record_cursor(bytes, 1024, 9, *b"CMB1").and_then(|mut cursor| {
            bounded_text(&mut cursor, 64).and_then(|stable_entry| {
                read_implementation_key(&mut cursor, implementation).and_then(|()| {
                    read_hashes(&mut cursor).and_then(|[pmf1_digest, state_schema_digest, negotiated_tuple_digest, initial_state_content_digest, protected_owner_binding_digest]| {
                        canonical_end(&cursor).and_then(|()| Self::new(CommunityMemberBindingInputV1 {
                            stable_entry, implementation, pmf1_digest, state_schema_digest,
                            negotiated_tuple_digest, initial_state_content_digest, protected_owner_binding_digest,
                        }))
                    })
                })
            })
        })
    }
}
