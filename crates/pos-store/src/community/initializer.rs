//! Installed catalogue initializer owner (ADR-129 revision 6, R6.1).
//!
//! The trusted composition root installs the exact canonical CSC1 bytes of
//! every CDP1 roster row here. This owner is the qualified protected owner
//! of catalogue State: it alone hashes and holds those bytes. At
//! installation it checks P8, `initializer_artifact_ref = [0x4353_0001,
//! len(CSC1), H(CSC1)]`, and that the CSC1 schema is the row's
//! `state_schema_digest`. A mismatch refuses installation, a composition
//! error and never a call result.
//!
//! No facade, request, guest or store row supplies or replaces initializer
//! bytes: nothing outside installation adds State here.

use std::collections::BTreeMap;

use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityDurableProfileV1, CommunityLifecycleErrorV1 as Error,
    CommunityStateContentV1, COMMUNITY_CLAIM_STATE_SCHEMA_V1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash};
use zeroize::Zeroizing;

use super::private_hash::private_digest;

/// The installed initializer owner of one CDP1 roster.
pub struct CommunityInitializerOwnerV1 {
    /// The CDP1 `authority_catalogue_digest`, H(CAP1) (P5).
    catalogue_digest: Hash,
    /// Canonical CSC1 bytes by `H(CSC1)`; rows sharing a State share one entry.
    states: BTreeMap<Hash, Zeroizing<Vec<u8>>>,
}

impl CommunityInitializerOwnerV1 {
    /// Install the exact CSC1 bytes of every roster row, in roster order, at
    /// the trusted composition root, which alone holds the
    /// [`AuthorityTrustRootSealV1`]. The seal only proves the caller is that
    /// root: the owner never evaluates authority, so it does not keep it.
    /// Without the seal it cannot be installed:
    ///
    /// ```compile_fail,E0061
    /// use pos_core::community_lifecycle::CommunityDurableProfileV1;
    /// use pos_store::community::CommunityInitializerOwnerV1;
    /// fn forge(profile: &CommunityDurableProfileV1<'_>, states: Vec<zeroize::Zeroizing<Vec<u8>>>) {
    ///     let _ = CommunityInitializerOwnerV1::new(profile, states);
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidBinding` (a composition refusal, R6.1(2)) when the
    /// number of States differs from the roster, a State is not a canonical
    /// CSC1, its ref `[0x4353_0001, len, H(CSC1)]` differs from its row's
    /// `initializer_artifact_ref`, or its schema differs from the row's
    /// `state_schema_digest`.
    pub fn new(
        _seal: &'static AuthorityTrustRootSealV1,
        profile: &CommunityDurableProfileV1<'_>,
        states: Vec<Zeroizing<Vec<u8>>>,
    ) -> Result<Self, Error> {
        let roster = profile.as_input().roster;
        if states.len() != roster.len() {
            return Err(Error::InvalidBinding);
        }
        let mut installed = BTreeMap::new();
        for (member, state) in roster.iter().zip(states) {
            let digest = private_digest(b"PiglorOS.Community.CSC1.v1", &[state.as_slice()]);
            let reference = ArtifactRefV1 {
                schema_id: COMMUNITY_CLAIM_STATE_SCHEMA_V1,
                byte_length: state.len() as u64,
                digest: *digest.as_bytes(),
            };
            let schema = CommunityStateContentV1::from_canonical_cbor(&state)
                .map(|content| content.schema_digest())
                .ok();
            if reference != member.initializer() || schema != Some(member.digests()[1]) {
                return Err(Error::InvalidBinding);
            }
            installed.insert(digest, state);
        }
        Ok(Self {
            catalogue_digest: profile.as_input().authority_catalogue_digest,
            states: installed,
        })
    }

    /// The CDP1 `authority_catalogue_digest` this owner was installed for.
    pub(super) const fn catalogue_digest(&self) -> Hash {
        self.catalogue_digest
    }

    /// Whether `digest` is the `H(CSC1)` of an installed State.
    pub(super) fn holds(&self, digest: Hash) -> bool {
        self.states.contains_key(&digest)
    }

    /// The installed canonical CSC1 bytes whose `H(CSC1)` is `digest`, for
    /// the generation's own protected copy (#560 A3c-2b′).
    pub(super) fn state(&self, digest: Hash) -> Option<&[u8]> {
        self.states.get(&digest).map(|state| state.as_slice())
    }
}
