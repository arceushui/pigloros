//! ADR-100 WKE1 key-evidence bytes and stable key identity.
//!
//! Structural decoding and content hashes do not prove a registry row or
//! authorize use. The installed owner must compare these bytes with its
//! immutable registration and live or tombstoned row under the release fence.

use crate::{
    encode_bytes, encode_hash, encode_head, Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1, PublicKey,
};

/// Maximum preferred-CBOR size of one WKE1 record.
pub const MAX_WORLD_KEY_EVIDENCE_BYTES_V1: usize = 256;

const EVIDENCE_DOMAIN: &[u8] = b"pigloros.world-evidence.key-evidence.v1\0";
const IDENTITY_DOMAIN: &[u8] = b"pigloros.world-evidence.key-identity.v1\0";

/// Closed structural errors; none reports key availability or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorldKeyEvidenceErrorV1 {
    /// Wrong CBOR type, width, magic, version, or trailing bytes.
    #[error("invalid WKE1 encoding")]
    InvalidEncoding,
    /// A field or the whole record exceeds its accepted bound.
    #[error("WKE1 field is out of bounds")]
    FieldOutOfBounds,
    /// The role, epoch, public-key presence, or material digest is invalid.
    #[error("invalid WKE1 key identity or material")]
    InvalidKey,
    /// The input has a nonpreferred CBOR representation.
    #[error("noncanonical WKE1 encoding")]
    NonCanonical,
}

/// Untrusted immutable evidence fields; no private material is carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldKeyEvidenceInputV1 {
    /// Exact owner, role and positive epoch.
    pub identity: KeyIdentityV1,
    /// Fingerprint of private material, never the material itself.
    pub private_material_digest: Hash,
    /// Whether this artifact actually needs retained private material.
    pub private_material_required: bool,
    /// Retained public key for signing roles; absent for encryption roles.
    pub public_verification_key: Option<PublicKey>,
}

/// Structurally valid WKE1 evidence, without a registry or use claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldKeyEvidenceV1(WorldKeyEvidenceInputV1);

impl WorldKeyEvidenceV1 {
    /// Validate one key-evidence record's structural fields.
    ///
    /// # Errors
    /// Rejects zero epoch or material digest and role/public-key mismatch.
    pub fn new(input: WorldKeyEvidenceInputV1) -> Result<Self, WorldKeyEvidenceErrorV1> {
        if input.identity.epoch == 0
            || input.private_material_digest == Hash::zero()
            || input.identity.role.is_signing() != input.public_verification_key.is_some()
        {
            Err(WorldKeyEvidenceErrorV1::InvalidKey)
        } else {
            Ok(Self(input))
        }
    }

    /// Borrow the validated but unauthenticated evidence fields.
    #[must_use]
    pub const fn as_input(&self) -> &WorldKeyEvidenceInputV1 {
        &self.0
    }

    /// Encode the exact eight-field preferred definite WKE1 record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(84);
        bytes.extend_from_slice(&[0x88, 0x44]);
        bytes.extend_from_slice(b"WKE1");
        bytes.push(1);
        encode_owner(&mut bytes, self.0.identity.owner_id);
        bytes.push(self.0.identity.role.code());
        encode_head(&mut bytes, 0, self.0.identity.epoch);
        encode_hash(&mut bytes, self.0.private_material_digest);
        bytes.push(if self.0.private_material_required {
            0xf5
        } else {
            0xf4
        });
        if let Some(key) = self.0.public_verification_key {
            encode_bytes(&mut bytes, key.as_bytes(), 2);
        } else {
            bytes.push(0xf6);
        }
        bytes
    }

    /// Ordinary BLAKE3 of the WKE1 domain and exact canonical bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_hash(EVIDENCE_DOMAIN, &self.to_canonical_cbor())
    }

    /// Stable identity hash, independent of private-material lifecycle.
    #[must_use]
    pub fn identity_digest(&self) -> Hash {
        let mut bytes = Vec::with_capacity(16 + self.0.identity.owner_id.as_str().len());
        bytes.push(0x83);
        encode_owner(&mut bytes, self.0.identity.owner_id);
        bytes.push(self.0.identity.role.code());
        encode_head(&mut bytes, 0, self.0.identity.epoch);
        domain_hash(IDENTITY_DOMAIN, &bytes)
    }

    /// Decode one bounded preferred-CBOR WKE1 record.
    ///
    /// # Errors
    /// Rejects malformed, oversized, noncanonical, or invalid key evidence.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, WorldKeyEvidenceErrorV1> {
        if bytes.len() > MAX_WORLD_KEY_EVIDENCE_BYTES_V1 {
            return Err(WorldKeyEvidenceErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader {
            cursor: crate::CborCursor::new(bytes),
        };
        reader
            .fixed(&[0x88, 0x44, b'W', b'K', b'E', b'1', 1])
            .and_then(|()| reader.owner())
            .and_then(|owner_id| reader.role().map(|role| (owner_id, role)))
            .and_then(|(owner_id, role)| {
                reader
                    .head(0)
                    .map(|epoch| KeyIdentityV1::from_parts(owner_id, role, epoch))
            })
            .and_then(|identity| reader.hash().map(|digest| (identity, digest)))
            .and_then(|(identity, private_material_digest)| {
                reader.boolean().map(|private_material_required| {
                    (identity, private_material_digest, private_material_required)
                })
            })
            .and_then(
                |(identity, private_material_digest, private_material_required)| {
                    reader.optional_public_key().map(|public_verification_key| {
                        WorldKeyEvidenceInputV1 {
                            identity,
                            private_material_digest,
                            private_material_required,
                            public_verification_key,
                        }
                    })
                },
            )
            .and_then(Self::new)
            .and_then(|record| {
                if !reader.cursor.is_finished() {
                    Err(WorldKeyEvidenceErrorV1::InvalidEncoding)
                } else if record.to_canonical_cbor() != bytes {
                    Err(WorldKeyEvidenceErrorV1::NonCanonical)
                } else {
                    Ok(record)
                }
            })
    }
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn encode_owner(out: &mut Vec<u8>, owner: OwnerIdV1) {
    let bytes = owner.as_str().as_bytes();
    // OwnerIdV1 enforces 1..=128 UTF-8 bytes, so one length byte suffices.
    let length = bytes.len().to_le_bytes()[0];
    if bytes.len() <= 23 {
        out.push(0x60 | length);
    } else {
        out.extend_from_slice(&[0x78, length]);
    }
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    cursor: crate::CborCursor<'a>,
}

impl Reader<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8], WorldKeyEvidenceErrorV1> {
        self.cursor
            .take(len)
            .map_err(|_| WorldKeyEvidenceErrorV1::InvalidEncoding)
    }

    fn fixed(&mut self, expected: &[u8]) -> Result<(), WorldKeyEvidenceErrorV1> {
        self.cursor
            .fixed(expected)
            .map_err(|_| WorldKeyEvidenceErrorV1::InvalidEncoding)
    }

    fn byte(&mut self) -> Result<u8, WorldKeyEvidenceErrorV1> {
        self.cursor
            .byte()
            .map_err(|_| WorldKeyEvidenceErrorV1::InvalidEncoding)
    }

    fn head(&mut self, major: u8) -> Result<u64, WorldKeyEvidenceErrorV1> {
        self.cursor
            .head(major)
            .map_err(|_| WorldKeyEvidenceErrorV1::InvalidEncoding)
    }

    fn owner(&mut self) -> Result<OwnerIdV1, WorldKeyEvidenceErrorV1> {
        self.head(3).and_then(|length| {
            if (1..=128).contains(&length) {
                self.take(usize::from(length.to_be_bytes()[7]))
                    .and_then(|part| {
                        std::str::from_utf8(part)
                            .map_err(|_| WorldKeyEvidenceErrorV1::InvalidEncoding)
                    })
                    .and_then(|owner| {
                        OwnerIdV1::new(owner).map_err(|_| WorldKeyEvidenceErrorV1::FieldOutOfBounds)
                    })
            } else {
                Err(WorldKeyEvidenceErrorV1::FieldOutOfBounds)
            }
        })
    }

    fn role(&mut self) -> Result<KeyRoleV1, WorldKeyEvidenceErrorV1> {
        self.head(0).and_then(|code| {
            u8::try_from(code)
                .map_err(|_| WorldKeyEvidenceErrorV1::InvalidKey)
                .and_then(|code| {
                    KeyRoleV1::from_code(code).map_err(|_| WorldKeyEvidenceErrorV1::InvalidKey)
                })
        })
    }

    fn hash(&mut self) -> Result<Hash, WorldKeyEvidenceErrorV1> {
        self.head(2).and_then(|length| {
            if length == 32 {
                self.take(32).map(|part| {
                    let mut bytes = [0; 32];
                    bytes.copy_from_slice(part);
                    Hash::from_bytes(bytes)
                })
            } else {
                Err(WorldKeyEvidenceErrorV1::InvalidEncoding)
            }
        })
    }

    fn boolean(&mut self) -> Result<bool, WorldKeyEvidenceErrorV1> {
        self.byte().and_then(|byte| match byte {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(WorldKeyEvidenceErrorV1::InvalidEncoding),
        })
    }

    fn optional_public_key(&mut self) -> Result<Option<PublicKey>, WorldKeyEvidenceErrorV1> {
        if self.cursor.consume_if(0xf6) {
            Ok(None)
        } else {
            self.hash()
                .map(|hash| Some(PublicKey::from_bytes(*hash.as_bytes())))
        }
    }
}
