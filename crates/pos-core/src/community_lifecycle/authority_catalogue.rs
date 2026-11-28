//! CAP1 community authority catalogue and its pinned derivations (ADR-129
//! revision 6, R6.2 and R6.4).
//!
//! CAP1 is the installed policy that every community administrative and
//! in-operation data-use decision is evaluated against. CDP1 and COB1
//! `authority_catalogue_digest` are exactly its digest H(CAP1). A CAP1 value
//! is data: it pins the authentication policy, actor mapping, policy
//! revisions and the capability attestation set, but it authenticates nobody
//! and admits no grant. The installed owner checks its pins at composition
//! and evaluates every request itself.

use super::{digest, is_valid_community_id_v1, record_prefix, CommunityLifecycleErrorV1 as Error};
use crate::{
    encode_bytes, encode_hash, encode_head, AuthorityRegistrySnapshotV1, AuthorityTrustRootSealV1,
    EntityId, Hash, TimelineId, MAX_AUTHORITY_TEXT_BYTES,
};

type Result<T> = std::result::Result<T, Error>;

/// Reference schema ID of a canonical AUD1 authorization decision (R6.4).
pub const COMMUNITY_AUD_SCHEMA_V1: u32 = 0x4341_0002;
/// Reference schema ID of a canonical PRN1 principal (R6.4).
pub const COMMUNITY_PRINCIPAL_SCHEMA_V1: u32 = 0x4341_0003;
/// Maximum complete CAP1 encoding.
pub const MAX_COMMUNITY_AUTHORITY_CATALOGUE_BYTES_V1: usize = 8_192;
/// Maximum CAP1 actor rows.
pub const MAX_COMMUNITY_ACTOR_ROWS_V1: usize = 64;

const MAPPING_PROFILE: &str = "pos.community.authority-mapping";
const MAPPING_PROFILE_VERSION: u64 = 6;

// Buffer sizes are plain literals, so no arithmetic mutant can survive in
// them; the assertions tie each one to the bounds it is derived from.
//
// CAP1 upper bound: record head and magic 7, version 1, profile 35, five
// hashes 170, two texts 2 * 130, rows head 2, 64 rows of 52 bytes and two
// 5-byte schema IDs.
const MAX_ENCODED_BYTES: usize = 3_813;
// The attestation preimage: array head 1, registry hash 34, bindings head 3
// and at most 128 bindings of 34 bytes.
const ATTESTATION_PREIMAGE_BYTES: usize = 4_390;
// The nonce preimage: array head 1, H(CAP1) 34 and three authority texts of
// at most 128 bytes with a 2-byte head each.
const NONCE_PREIMAGE_BYTES: usize = 425;
// The execution nonce preimage (R8.1(4)): array head 1, H(CAP1) 34, T 17,
// the text `execute` 8 and the 54-byte operation constraint with a 2-byte
// head, 116 bytes in all.
const EXECUTION_NONCE_PREIMAGE_BYTES: usize = 116;
/// Rows of one `ExecutionAuthority` digest: one per roster member (R8.1(6)).
const MAX_EXECUTION_AUTHORITY_ROWS: usize = 64;
const _: () = assert!(MAX_COMMUNITY_ACTOR_ROWS_V1 == 64);
const _: () = assert!(MAX_AUTHORITY_TEXT_BYTES == 128);
const _: () = assert!(crate::MAX_AUTHORITY_REGISTRY_BINDINGS == 128);
const _: () = assert!(MAX_ENCODED_BYTES <= MAX_COMMUNITY_AUTHORITY_CATALOGUE_BYTES_V1);

/// One CAP1 actor row: the installed actor entity for one principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityActorRowV1 {
    /// `principal_digest_v1` of the authenticated principal.
    pub principal_digest: Hash,
    /// The actor entity the request names for that principal.
    pub actor_entity_id: EntityId,
}

/// Untrusted CAP1 fields; the mapping profile and schema IDs are fixed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityAuthorityCatalogueInputV1 {
    /// `ForkAuthenticationPolicyV1::digest()` of the installed community FAP1.
    pub fap1_digest: Hash,
    /// The installed lifecycle host audience identity (A5.1).
    pub audience: String,
    /// 1..64 actor rows, strictly ascending by principal digest.
    pub actor_rows: Vec<CommunityActorRowV1>,
    /// Pinned capability policy revision.
    pub capability_policy_revision: Hash,
    /// Pinned consent policy revision.
    pub consent_policy_revision: Hash,
    /// Pinned authority registry digest.
    pub authority_registry_digest: Hash,
    /// Digest of the installed capability attestation snapshot.
    pub capability_attestation_digest: Hash,
    /// ADR-103 trust scope of every roster member.
    pub trust_scope: String,
}

/// Exact thirteen-field CAP1 policy data; it grants no authority.
///
/// CAP1 is built only at composition, from validated fields, and is used as
/// installed data and through its digest. It has no decoder by design; a
/// strict one belongs with the first loader that reads CAP1 bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityAuthorityCatalogueV1(CommunityAuthorityCatalogueInputV1);

impl CommunityAuthorityCatalogueV1 {
    /// Validate every CAP1 field bound. Only the trusted composition root,
    /// which holds the [`AuthorityTrustRootSealV1`], builds a CAP1 (#1374):
    ///
    /// ```compile_fail,E0061
    /// use pos_core::community_lifecycle::{
    ///     CommunityAuthorityCatalogueInputV1, CommunityAuthorityCatalogueV1,
    /// };
    /// fn forge(input: CommunityAuthorityCatalogueInputV1) {
    ///     let _ = CommunityAuthorityCatalogueV1::new(input);
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero digest, revision, principal or
    /// actor, unordered or repeated actor rows, or a trust scope outside the
    /// `plugin_trust` identifier grammar; `BoundsExceeded` for an empty or
    /// over-128-byte audience and for zero or more than 64 actor rows.
    pub fn new(
        _seal: &AuthorityTrustRootSealV1,
        input: CommunityAuthorityCatalogueInputV1,
    ) -> Result<Self> {
        if !(1..=MAX_AUTHORITY_TEXT_BYTES).contains(&input.audience.len())
            || !(1..=MAX_COMMUNITY_ACTOR_ROWS_V1).contains(&input.actor_rows.len())
        {
            return Err(Error::BoundsExceeded);
        }
        let zero_link = [
            input.fap1_digest,
            input.capability_policy_revision,
            input.consent_policy_revision,
            input.authority_registry_digest,
            input.capability_attestation_digest,
        ]
        .contains(&Hash::zero());
        let invalid_row = input.actor_rows.iter().any(|row| {
            row.principal_digest == Hash::zero()
                || row.actor_entity_id.inner().to_bytes() == [0; 16]
        });
        let unordered = !input
            .actor_rows
            .windows(2)
            .all(|pair| pair[0].principal_digest < pair[1].principal_digest);
        if zero_link || invalid_row || unordered || !is_valid_community_id_v1(&input.trust_scope) {
            Err(Error::InvalidBinding)
        } else {
            Ok(Self(input))
        }
    }

    /// Borrow the validated fields.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityAuthorityCatalogueInputV1 {
        &self.0
    }

    /// The actor entity CAP1 maps `principal_digest` to, if any (R6.2(4)).
    #[must_use]
    pub fn actor_for(&self, principal_digest: Hash) -> Option<EntityId> {
        self.0
            .actor_rows
            .binary_search_by(|row| row.principal_digest.cmp(&principal_digest))
            .ok()
            .map(|index| self.0.actor_rows[index].actor_entity_id)
    }

    /// Encode the exact preferred CAP1.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let input = self.as_input();
        let mut out = Vec::with_capacity(MAX_ENCODED_BYTES);
        record_prefix(&mut out, 13, *b"CAP1");
        encode_head(&mut out, 4, 2);
        encode_bytes(&mut out, MAPPING_PROFILE.as_bytes(), 3);
        encode_head(&mut out, 0, MAPPING_PROFILE_VERSION);
        encode_hash(&mut out, input.fap1_digest);
        encode_bytes(&mut out, input.audience.as_bytes(), 3);
        encode_head(&mut out, 4, input.actor_rows.len() as u64);
        for row in &input.actor_rows {
            encode_head(&mut out, 4, 2);
            encode_hash(&mut out, row.principal_digest);
            encode_bytes(&mut out, &row.actor_entity_id.inner().to_bytes(), 2);
        }
        for hash in [
            input.capability_policy_revision,
            input.consent_policy_revision,
            input.authority_registry_digest,
            input.capability_attestation_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        encode_bytes(&mut out, input.trust_scope.as_bytes(), 3);
        encode_head(&mut out, 0, u64::from(COMMUNITY_AUD_SCHEMA_V1));
        encode_head(&mut out, 0, u64::from(COMMUNITY_PRINCIPAL_SCHEMA_V1));
        out
    }

    /// H(CAP1), the CDP1 and COB1 `authority_catalogue_digest`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CAP1.v1\0", &self.to_canonical_cbor())
    }
}

/// `H("CapabilityAttestation", preferred [registry_digest, sorted
/// capability_bindings])` of an installed attestation snapshot (R6.2(2)).
#[must_use]
pub fn community_capability_attestation_digest_v1(snapshot: &AuthorityRegistrySnapshotV1) -> Hash {
    let bindings = snapshot.capability_bindings();
    let mut preimage = Vec::with_capacity(ATTESTATION_PREIMAGE_BYTES);
    encode_head(&mut preimage, 4, 2);
    encode_hash(&mut preimage, snapshot.registry_digest());
    encode_head(&mut preimage, 4, bindings.len() as u64);
    for binding in bindings {
        encode_hash(&mut preimage, *binding);
    }
    digest(b"PiglorOS.Community.CapabilityAttestation.v1\0", &preimage)
}

/// The FAE1 `operation_nonce` one `run_pass` call requires (R8.1(4)).
///
/// It is `H("ExecutionNonce", preferred [H(CAP1), T, "execute",
/// operation_constraint_text])`, with `operation_constraint_text` the
/// `community.operation:r:<O32>` constraint of the call's reservation
/// operation. It binds one catalogue, one Timeline and one reservation
/// operation, never an administrative call (its domain differs from
/// [`community_authentication_nonce_v1`]'s).
#[must_use]
pub fn community_execution_nonce_v1(
    catalogue_digest: Hash,
    timeline: TimelineId,
    operation_constraint: &str,
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(EXECUTION_NONCE_PREIMAGE_BYTES);
    encode_head(&mut preimage, 4, 4);
    encode_hash(&mut preimage, catalogue_digest);
    encode_bytes(&mut preimage, &timeline.inner().to_bytes(), 2);
    encode_bytes(&mut preimage, b"execute", 3);
    encode_bytes(&mut preimage, operation_constraint.as_bytes(), 3);
    *digest(b"PiglorOS.Community.ExecutionNonce.v1\0", &preimage).as_bytes()
}

/// The CRI1 `authority_request_digest` of a `run_pass` call (R8.1(6)).
///
/// It is `H("ExecutionAuthority", preferred rows)`, one row
/// `[CMB1_digest, request_digest]` per roster member in the generation's
/// CGI1 `ordered_CMB1_digests` order. `request_digest` is
/// `AuthorizationRequestV1::binding_digest` of that member's request.
///
/// # Errors
/// Returns `InvalidBinding` for no row and for more than 64 rows.
pub fn community_execution_authority_digest_v1(rows: &[(Hash, Hash)]) -> Result<Hash> {
    if rows.is_empty() || rows.len() > MAX_EXECUTION_AUTHORITY_ROWS {
        return Err(Error::InvalidBinding);
    }
    let mut preimage = Vec::with_capacity(1 + rows.len() * 69);
    encode_head(&mut preimage, 4, rows.len() as u64);
    for (member, request) in rows {
        encode_head(&mut preimage, 4, 2);
        encode_hash(&mut preimage, *member);
        encode_hash(&mut preimage, *request);
    }
    Ok(digest(
        b"PiglorOS.Community.ExecutionAuthority.v1\0",
        &preimage,
    ))
}

/// The FAE1 `operation_nonce` one administrative call requires (R6.2(3)(ii)):
/// `H("AuthenticationNonce", preferred [H(CAP1), resource, action,
/// operation_constraint])`.
#[must_use]
pub fn community_authentication_nonce_v1(
    catalogue_digest: Hash,
    resource: &str,
    action: &str,
    operation_constraint: &str,
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(NONCE_PREIMAGE_BYTES);
    encode_head(&mut preimage, 4, 4);
    encode_hash(&mut preimage, catalogue_digest);
    for text in [resource, action, operation_constraint] {
        encode_bytes(&mut preimage, text.as_bytes(), 3);
    }
    *digest(b"PiglorOS.Community.AuthenticationNonce.v1\0", &preimage).as_bytes()
}
