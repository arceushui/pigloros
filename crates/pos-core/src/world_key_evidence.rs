//! ADR-100 WKE1 key-evidence bytes and stable key identity.
//!
//! Structural decoding and content hashes do not prove a registry row or
//! authorize use. [`resolve_coordinator_key_evidence_v1`] compares the
//! retained coordinator WKE1 of an LCQ1 or MSR1 with the registry's
//! immutable live or tombstoned row; the owner commits and the historical
//! owner-link verifier both call it.

use crate::{
    encode_bytes, encode_hash, encode_head, Hash, KeyIdentityV1, KeyRegistryPortV1, KeyRoleV1,
    OwnerIdV1, PublicKey,
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

/// One installed-coordinator receipt with the exact WKE1 bytes it names.
///
/// The signing hooks return this pair; `key_evidence` is unverified until the
/// owner commit resolves it with [`resolve_coordinator_key_evidence_v1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorSignedReceiptV1<R> {
    /// The signed LCQ1 or MSR1 receipt.
    pub receipt: R,
    /// Exact canonical WKE1 bytes that the receipt's evidence hash names.
    pub key_evidence: Vec<u8>,
}

/// One coordinator key-evidence record: its address and exact WKE1 bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorKeyEvidenceV1 {
    /// The receipt's `coordinator_key_evidence_hash`.
    pub evidence_hash: Hash,
    /// Exact WKE1 bytes the installed coordinator returned for that address.
    pub bytes: Vec<u8>,
}

impl CoordinatorKeyEvidenceV1 {
    /// Resolve these bytes against `keys`, as
    /// [`resolve_coordinator_key_evidence_v1`] does.
    ///
    /// # Errors
    /// Returns the resolver's closed rejection.
    pub fn resolve(
        &self,
        keys: &dyn KeyRegistryPortV1,
    ) -> Result<WorldKeyEvidenceV1, CoordinatorKeyEvidenceErrorV1> {
        resolve_coordinator_key_evidence_v1(&self.bytes, self.evidence_hash, keys)
    }
}

/// Closed reasons why retained coordinator key evidence names no signer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CoordinatorKeyEvidenceErrorV1 {
    /// The bytes are not one canonical WKE1 record with the receipt's address.
    #[error("coordinator key evidence is not the receipt's exact WKE1 record")]
    InvalidEvidence,
    /// The WKE1 record is not the verify-only Timeline-integrity signing form.
    #[error("coordinator key evidence has the wrong role or private-material use")]
    WrongKeyUse,
    /// No registry row has the WKE1 identity, material and public key.
    #[error("coordinator key evidence does not match the key registry")]
    UnregisteredKey,
}

/// Resolve retained LCQ1 or MSR1 coordinator WKE1 bytes against the registry.
///
/// The bytes must be one canonical WKE1 record whose digest is the receipt's
/// `coordinator_key_evidence_hash`, in the ADR-100 historical-signature
/// verifier form: `TimelineIntegritySigning`, no private material required,
/// and a retained public verification key (a structurally valid signing WKE1
/// always carries one). `keys` must then hold the exact identity's record with
/// that public key, and its live material digest, or the tombstone's destroyed
/// material digest once the key was destroyed, must equal the evidence's. A
/// later rotated or tombstoned key therefore still resolves (ADR-065 §2).
///
/// This proves which registered key the evidence names; the installed hook
/// still verifies the receipt signature itself.
///
/// # Errors
/// Returns `InvalidEvidence` for undecodable bytes or another address,
/// `WrongKeyUse` for another role or a private-material requirement, and
/// `UnregisteredKey` when no matching registry row exists.
pub fn resolve_coordinator_key_evidence_v1(
    bytes: &[u8],
    evidence_hash: Hash,
    keys: &dyn KeyRegistryPortV1,
) -> Result<WorldKeyEvidenceV1, CoordinatorKeyEvidenceErrorV1> {
    let evidence = WorldKeyEvidenceV1::from_canonical_cbor(bytes)
        .ok()
        .filter(|evidence| evidence.digest() == evidence_hash)
        .ok_or(CoordinatorKeyEvidenceErrorV1::InvalidEvidence)?;
    let input = evidence.as_input();
    if input.identity.role != KeyRoleV1::TimelineIntegritySigning || input.private_material_required
    {
        return Err(CoordinatorKeyEvidenceErrorV1::WrongKeyUse);
    }
    let identity = input.identity;
    let registered = keys.key_record(identity).is_some_and(|record| {
        let material = record.private_material_digest.or_else(|| {
            keys.tombstone(identity)
                .map(|tombstone| tombstone.destroyed_material_digest)
        });
        record.identity == identity
            && material == Some(input.private_material_digest)
            && record.public_verification_key == input.public_verification_key
    });
    if registered {
        Ok(evidence)
    } else {
        Err(CoordinatorKeyEvidenceErrorV1::UnregisteredKey)
    }
}

/// Owner of the shared `test-support` coordinator signing key.
#[cfg(any(test, feature = "test-support"))]
pub const TEST_COORDINATOR_OWNER: &str = "test-coordinator";

/// The `test-support` verify-only WKE1 of the shared coordinator key.
///
/// Epoch zero is reserved, so it is raised to one. The material digest and
/// public key repeat the epoch byte, so distinct epochs never reuse material.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn test_coordinator_key_evidence(epoch: u8) -> WorldKeyEvidenceV1 {
    let seed = epoch.max(1);
    WorldKeyEvidenceV1(WorldKeyEvidenceInputV1 {
        identity: KeyIdentityV1::from_parts(
            OwnerIdV1::from_static(TEST_COORDINATOR_OWNER),
            KeyRoleV1::TimelineIntegritySigning,
            u64::from(seed),
        ),
        private_material_digest: Hash::from_bytes([seed; 32]),
        private_material_required: false,
        public_verification_key: Some(PublicKey::from_bytes([seed; 32])),
    })
}

/// The `test-support` registration that matches one coordinator WKE1.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub const fn test_coordinator_key_registration(
    evidence: &WorldKeyEvidenceV1,
) -> crate::KeyRegistrationV1 {
    crate::KeyRegistrationV1::new(
        evidence.0.identity,
        evidence.0.private_material_digest,
        evidence.0.public_verification_key,
    )
}

/// A `test-support` key registry holding the epoch-1 coordinator key.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn test_coordinator_key_registry() -> crate::KeyRegistryStateV1 {
    let mut registry = crate::KeyRegistryStateV1::new();
    // A fresh registry always accepts the first epoch of a role.
    let _registered = registry.register_key(test_coordinator_key_registration(
        &test_coordinator_key_evidence(1),
    ));
    registry
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
