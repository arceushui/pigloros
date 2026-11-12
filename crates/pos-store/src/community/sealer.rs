//! Metadata sealing: owner commitment, COH1/COE1, then the CNE1 envelope.
//!
//! The header is derived from the CSM1 scope cover alone, so the anchor
//! Timeline/generation, the protection Control identity and the cover digest
//! cannot drift between the AEAD context and the stored envelope.

use pos_core::community_lifecycle::{
    CommunityArtifactHeaderInputV1, CommunityArtifactHeaderV1, CommunityArtifactKindV1,
    CommunityArtifactOperationV1, CommunityArtifactPurposeV1, CommunityEncryptedEnvelopeV1,
    CommunityLifecycleErrorV1 as Error, CommunityMetadataEnvelopeV1, CommunityMetadataSchemaV1,
    CommunityMetadataScopeV1,
};
use pos_core::Hash;
use pos_crypto::community_cipher::CommunityArtifactCipherV1;
use zeroize::Zeroizing;

use super::private_hash::plaintext_commitment;

const KIND: CommunityArtifactKindV1 = CommunityArtifactKindV1::LifecycleControl;

/// One sealed CNE1 with its physical address and private owner commitment.
pub(super) struct SealedMetadataV1 {
    pub(super) envelope: Zeroizing<Vec<u8>>,
    pub(super) address: Hash,
    pub(super) commitment: Hash,
}

/// Seal one exact metadata record under the scope cover's Control key.
pub(super) fn seal_metadata(
    cipher: &mut CommunityArtifactCipherV1,
    scope: &CommunityMetadataScopeV1<'_>,
    schema: CommunityMetadataSchemaV1,
    plaintext: &[u8],
) -> Result<SealedMetadataV1, Error> {
    let cover = scope.as_input();
    CommunityArtifactHeaderV1::new(CommunityArtifactHeaderInputV1 {
        timeline: cover.metadata_anchor_timeline,
        generation: cover.metadata_anchor_generation,
        purpose: CommunityArtifactPurposeV1::LifecycleControl,
        operation: CommunityArtifactOperationV1::Control(cover.protection_operation_id),
        record_kind: KIND,
        scope_cover_digest: scope.digest(),
        evidence_not_after_micros: cover.metadata_not_after_micros,
    })
    .and_then(|header| {
        cipher
            .seal(plaintext, header.associated_data_digest().as_bytes())
            .ok()
            .ok_or(Error::CapacityExhausted)
            .and_then(|sealed| {
                CommunityEncryptedEnvelopeV1::new(
                    header,
                    *sealed.nonce(),
                    sealed.ciphertext_and_tag(),
                )
                .map(|envelope| envelope.to_canonical_cbor())
            })
    })
    .and_then(|envelope| {
        let cover_bytes = scope.to_canonical_cbor();
        CommunityMetadataEnvelopeV1::new(schema, &cover_bytes, &envelope).map(|framed| {
            SealedMetadataV1 {
                address: framed.address(),
                envelope: framed.to_canonical_cbor(),
                commitment: plaintext_commitment(KIND, plaintext),
            }
        })
    })
}

/// Authenticate one CNE1 and return its plaintext only if it is the exact
/// stored envelope and committed record. The address covers the clear schema
/// label; the caller's record decoder still checks the authenticated magic.
pub(super) fn open_metadata(
    cipher: &CommunityArtifactCipherV1,
    sealed: &SealedMetadataV1,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    CommunityMetadataEnvelopeV1::from_canonical_cbor(&sealed.envelope)
        .ok()
        .filter(|framed| framed.address() == sealed.address)
        .and_then(|framed| {
            let envelope = framed.envelope();
            cipher
                .open(
                    envelope.nonce(),
                    envelope.ciphertext_and_tag(),
                    envelope.header().associated_data_digest().as_bytes(),
                )
                .ok()
        })
        .filter(|plaintext| plaintext_commitment(KIND, plaintext) == sealed.commitment)
        .ok_or(Error::EvidenceUnavailable)
}
