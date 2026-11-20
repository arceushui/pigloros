//! Protected artifact framing and historical admission data, never use grants.

use super::{
    bounded_bytes, canonical_end, digest, read_hashes, read_head, record_cursor, record_prefix,
    validate_horizon, CommunityArtifactKindV1, CommunityEncryptedEnvelopeV1,
    CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, Hash};
use zeroize::Zeroizing;

const MAX_OBJECT: usize = 4 * 1024 * 1024;
const MAX_ENVELOPE: usize = 3_147_840;
const MAX_PROOF_PLAINTEXT: usize = 512 * 1024;

/// Exact borrowed COW1 bytes. Neither envelope has been authenticated by parsing.
pub struct CommunityProtectedObjectV1<'a> {
    content_envelope: &'a [u8],
    proof_envelope: &'a [u8],
}

impl<'a> CommunityProtectedObjectV1<'a> {
    /// Check both canonical envelopes, proof size and shared key/context fields.
    ///
    /// # Errors
    /// Rejects malformed envelopes, a non-proof companion, a proof over512KiB,
    /// or different T/G/purpose/operation/scope/horizon. Authentication, CAR1
    /// comparison, source extraction and current admission remain owner work.
    pub fn new(content_envelope: &'a [u8], proof_envelope: &'a [u8]) -> Result<Self> {
        CommunityEncryptedEnvelopeV1::from_canonical_cbor(content_envelope).and_then(|content| {
            CommunityEncryptedEnvelopeV1::from_canonical_cbor(proof_envelope).and_then(|proof| {
                if proof.ciphertext_and_tag().len() > MAX_PROOF_PLAINTEXT + 16 {
                    return Err(Error::BoundsExceeded);
                }
                let content_header = content.header().as_input();
                let proof_header = proof.header().as_input();
                let expected_proof_header = super::CommunityArtifactHeaderInputV1 {
                    record_kind: CommunityArtifactKindV1::ClassificationProof,
                    ..*content_header
                };
                if *proof_header == expected_proof_header {
                    Ok(Self {
                        content_envelope,
                        proof_envelope,
                    })
                } else {
                    Err(Error::InvalidBinding)
                }
            })
        })
    }

    /// Borrow exact canonical COE1; no plaintext or key is exposed.
    #[must_use]
    pub const fn content_envelope(&self) -> &'a [u8] {
        self.content_envelope
    }

    /// Borrow exact encrypted CAR1 companion COE1.
    #[must_use]
    pub const fn proof_envelope(&self) -> &'a [u8] {
        self.proof_envelope
    }

    /// Encode exact four-field COW1, reserving all space before writing.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            self.content_envelope.len() + self.proof_envelope.len() + 32,
        ));
        record_prefix(&mut out, 4, *b"COW1");
        encode_bytes(&mut out, self.content_envelope, 2);
        encode_bytes(&mut out, self.proof_envelope, 2);
        out
    }

    /// Physical COW1 address; distinct from the existing ARD1 artifact digest.
    #[must_use]
    pub fn address(&self) -> Hash {
        digest(
            b"PiglorOS.Community.ProtectedObject.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Parse one complete COW1, borrowing both potentially large envelopes.
    ///
    /// # Errors
    /// Rejects invalid nested envelopes/bindings, framing, bounds and trailers.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_OBJECT, 4, *b"COW1").and_then(|mut cursor| {
            bounded_bytes(&mut cursor, MAX_ENVELOPE).and_then(|content| {
                bounded_bytes(&mut cursor, MAX_ENVELOPE)
                    .and_then(|proof| Self::new(content, proof))
                    .and_then(|record| canonical_end(&cursor).map(|()| record))
            })
        })
    }
}

/// Untrusted immutable COA1 bindings, not independently verified authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityArtifactAdmissionInputV1 {
    /// Physical protected COW1 address.
    pub protected_object_address: Hash,
    /// Existing class/length-bound ARD1 artifact digest, not the COW1 address.
    pub artifact_digest: Hash,
    /// Exact ARD1 registration address.
    pub registration_address: Hash,
    /// Exact COB1 owner-binding evidence commitment.
    pub owner_binding_digest: Hash,
    /// Exact complete CSB1 scope-cover commitment.
    pub scope_cover_digest: Hash,
    /// Original horizon; discovery cannot extend it.
    pub evidence_not_after_micros: u64,
    /// Original inventory observation; zero is a valid initial generation.
    pub admission_inventory_generation: u64,
    /// Exact CAU1 current-admission evidence commitment, not historical CPV1.
    pub authority_evidence_digest: Hash,
}

/// Structural COA1 record. Later use still requires fresh authority and fences.
pub struct CommunityArtifactAdmissionV1(CommunityArtifactAdmissionInputV1);

impl CommunityArtifactAdmissionV1 {
    /// Check nonzero links and a positive i64-bounded absolute horizon.
    ///
    /// # Errors
    /// Rejects zero commitments or an invalid horizon. A successful constructor
    /// verifies no authority, inventory, classification or physical object.
    pub fn new(input: CommunityArtifactAdmissionInputV1) -> Result<Self> {
        if [
            input.protected_object_address,
            input.artifact_digest,
            input.registration_address,
            input.owner_binding_digest,
            input.scope_cover_digest,
            input.authority_evidence_digest,
        ]
        .contains(&Hash::zero())
        {
            return Err(Error::InvalidBinding);
        }
        validate_horizon(input.evidence_not_after_micros).map(|()| Self(input))
    }

    /// Borrow historical binding data without minting a current read permit.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityArtifactAdmissionInputV1 {
        &self.0
    }

    /// Encode exact ten-field COA1 in private pre-sized staging.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 10, *b"COA1");
        for hash in [
            input.protected_object_address,
            input.artifact_digest,
            input.registration_address,
            input.owner_binding_digest,
            input.scope_cover_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        encode_head(&mut out, 0, input.admission_inventory_generation);
        encode_hash(&mut out, input.authority_evidence_digest);
        out
    }

    /// Derive historical COA1 identity; hashing cannot establish admission.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(
            b"PiglorOS.Community.ArtifactAdmission.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode one preferred COA1 while retaining no raw evidence or payload.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/oversized or locally invalid data.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 1024, 10, *b"COA1").and_then(|mut cursor| {
            read_hashes(&mut cursor).and_then(
                |[protected_object_address, artifact_digest, registration_address, owner_binding_digest, scope_cover_digest]| {
                    read_head(&mut cursor, 0).and_then(|evidence_not_after_micros| {
                        read_head(&mut cursor, 0).and_then(|admission_inventory_generation| {
                            super::read_hash(&mut cursor).and_then(|authority_evidence_digest| {
                                Self::new(CommunityArtifactAdmissionInputV1 {
                                    protected_object_address,
                                    artifact_digest,
                                    registration_address,
                                    owner_binding_digest,
                                    scope_cover_digest,
                                    evidence_not_after_micros,
                                    admission_inventory_generation,
                                    authority_evidence_digest,
                                }).and_then(|record| canonical_end(&cursor).map(|()| record))
                            })
                        })
                    })
                },
            )
        })
    }
}
