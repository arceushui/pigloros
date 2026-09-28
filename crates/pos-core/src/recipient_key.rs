//! Public recipient-key descriptors for recipient-bound Timeline export.
//!
//! RKP1 carries public routing material only. Private recipient key bytes stay
//! with the owning adapter outside `pos-core`.

use crate::{EntityId, Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1};

const MAGIC: [u8; 4] = *b"RKP1";
const VERSION: u8 = 1;
const ROLE_CODE: u8 = 4;
const KEM_CODE: u16 = 0x0020;
const OWNER_PREFIX: &[u8; 10] = b"recipient:";
const OWNER_LENGTH: usize = 42;
const OWNER_LENGTH_U8: u8 = 42;
const FINGERPRINT_DOMAIN: &[u8] = b"pigloros/recipient-key-descriptor/v1\0";

/// Closed failures for the RKP1 public descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecipientKeyDescriptorErrorV1 {
    /// The descriptor bytes are not the exact RKP1 representation.
    #[error("recipient key descriptor encoding is invalid")]
    InvalidEncoding,
    /// The descriptor uses an unsupported schema version.
    #[error("recipient key descriptor version is unsupported")]
    UnsupportedVersion,
    /// The descriptor does not name the recipient-encryption role.
    #[error("recipient key descriptor role is invalid")]
    InvalidRole,
    /// The descriptor does not use DHKEM(X25519, HKDF-SHA256).
    #[error("recipient key descriptor KEM is invalid")]
    InvalidKem,
    /// The recipient epoch is zero.
    #[error("recipient key descriptor epoch is invalid")]
    InvalidEpoch,
    /// The owner is not an exact recipient owner derived from an `EntityId`.
    #[error("recipient key descriptor owner is invalid")]
    InvalidOwner,
}

/// Derive the sole V1 recipient owner for one consent grantee.
///
/// The result is exactly `recipient:` followed by the lowercase hexadecimal
/// representation of the grantee's canonical 16-byte `EntityId`.
///
/// # Errors
///
/// Returns [`RecipientKeyDescriptorErrorV1::InvalidOwner`] only if the
/// internally constructed owner cannot satisfy the registry owner contract.
pub fn recipient_owner_id_from_grantee(
    grantee_id: EntityId,
) -> Result<OwnerIdV1, RecipientKeyDescriptorErrorV1> {
    let mut owner = Vec::with_capacity(OWNER_LENGTH);
    owner.extend_from_slice(OWNER_PREFIX);
    for byte in u128::from(grantee_id.inner()).to_be_bytes() {
        owner.push(hex_digit(byte >> 4));
        owner.push(hex_digit(byte & 0x0f));
    }
    String::from_utf8(owner)
        .map_err(|_| RecipientKeyDescriptorErrorV1::InvalidOwner)
        .and_then(|owner| {
            OwnerIdV1::new(owner).map_err(|_| RecipientKeyDescriptorErrorV1::InvalidOwner)
        })
}

/// The exact public RKP1 descriptor for one enrolled recipient epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientKeyDescriptorV1 {
    identity: KeyIdentityV1,
    public_key: [u8; 32],
}

impl RecipientKeyDescriptorV1 {
    /// Construct a recipient descriptor bound to the supplied consent grantee.
    ///
    /// The owner and role are derived by this constructor; callers cannot
    /// substitute either with an arbitrary registry identity.
    ///
    /// # Errors
    ///
    /// Returns [`RecipientKeyDescriptorErrorV1::InvalidEpoch`] for epoch zero.
    pub fn for_grantee(
        grantee_id: EntityId,
        epoch: u64,
        public_key: [u8; 32],
    ) -> Result<Self, RecipientKeyDescriptorErrorV1> {
        if epoch == 0 {
            return Err(RecipientKeyDescriptorErrorV1::InvalidEpoch);
        }
        recipient_owner_id_from_grantee(grantee_id).map(|owner_id| Self {
            identity: KeyIdentityV1::from_parts(
                owner_id,
                KeyRoleV1::ExportRecipientEncryption,
                epoch,
            ),
            public_key,
        })
    }

    /// Decode and validate exact canonical RKP1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed error for any noncanonical, malformed, or unsupported
    /// descriptor.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecipientKeyDescriptorErrorV1> {
        let mut cursor = Rkp1Cursor::new(bytes);
        cursor.array_start()?;
        cursor.exact_magic()?;
        cursor.exact_u8(VERSION, RecipientKeyDescriptorErrorV1::UnsupportedVersion)?;
        let owner = cursor.owner()?;
        cursor.exact_u8(ROLE_CODE, RecipientKeyDescriptorErrorV1::InvalidRole)?;
        let epoch = cursor.unsigned()?;
        if epoch == 0 {
            return Err(RecipientKeyDescriptorErrorV1::InvalidEpoch);
        }
        cursor.exact_u16(KEM_CODE, RecipientKeyDescriptorErrorV1::InvalidKem)?;
        let public_key = cursor.public_key()?;
        if cursor.is_finished() {
            Ok(Self::from_parts(owner, epoch, public_key))
        } else {
            Err(RecipientKeyDescriptorErrorV1::InvalidEncoding)
        }
    }

    /// Return this descriptor's exact canonical RKP1 bytes.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(86);
        bytes.push(0x87);
        bytes.push(0x44);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&[0x78, OWNER_LENGTH_U8]);
        bytes.extend_from_slice(self.identity.owner_id.as_str().as_bytes());
        bytes.push(ROLE_CODE);
        encode_unsigned(self.identity.epoch, &mut bytes);
        bytes.extend_from_slice(&[0x18, KEM_CODE.to_be_bytes()[1]]);
        bytes.extend_from_slice(&[0x58, 32]);
        bytes.extend_from_slice(&self.public_key);
        bytes
    }

    /// Return the exact registered recipient identity.
    #[must_use]
    pub const fn identity(self) -> KeyIdentityV1 {
        self.identity
    }

    /// Return the exact X25519 public key.
    #[must_use]
    pub const fn public_key(self) -> [u8; 32] {
        self.public_key
    }

    /// Return whether this descriptor is bound to this exact consent grantee.
    #[must_use]
    pub fn is_for_grantee(self, grantee_id: EntityId) -> bool {
        recipient_owner_id_from_grantee(grantee_id)
            .is_ok_and(|owner| owner == self.identity.owner_id)
    }

    /// Return the display fingerprint over exact canonical RKP1 bytes.
    #[must_use]
    pub fn fingerprint(self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update(&self.encode());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    const fn from_parts(owner_id: OwnerIdV1, epoch: u64, public_key: [u8; 32]) -> Self {
        Self {
            identity: KeyIdentityV1::from_parts(
                owner_id,
                KeyRoleV1::ExportRecipientEncryption,
                epoch,
            ),
            public_key,
        }
    }
}

fn hex_digit(value: u8) -> u8 {
    b"0123456789abcdef"[usize::from(value)]
}

fn is_recipient_owner(owner: &OwnerIdV1) -> bool {
    let bytes = owner.as_str().as_bytes();
    bytes.len() == OWNER_LENGTH
        && bytes.starts_with(OWNER_PREFIX)
        && bytes[OWNER_PREFIX.len()..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn encode_unsigned(value: u64, bytes: &mut Vec<u8>) {
    match value {
        0..=23 => bytes.push(value.to_be_bytes()[7]),
        24..=0xff => bytes.extend_from_slice(&[0x18, value.to_be_bytes()[7]]),
        0x100..=0xffff => {
            bytes.push(0x19);
            bytes.extend_from_slice(&value.to_be_bytes()[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            bytes.push(0x1a);
            bytes.extend_from_slice(&value.to_be_bytes()[4..]);
        }
        _ => {
            bytes.push(0x1b);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct Rkp1Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Rkp1Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn array_start(&mut self) -> Result<(), RecipientKeyDescriptorErrorV1> {
        self.exact_byte(0x87)
    }

    fn exact_magic(&mut self) -> Result<(), RecipientKeyDescriptorErrorV1> {
        self.exact_byte(0x44)?;
        self.take(MAGIC.len()).and_then(|actual| {
            (actual == MAGIC)
                .then_some(())
                .ok_or(RecipientKeyDescriptorErrorV1::InvalidEncoding)
        })
    }

    fn exact_u8(
        &mut self,
        expected: u8,
        error: RecipientKeyDescriptorErrorV1,
    ) -> Result<(), RecipientKeyDescriptorErrorV1> {
        self.exact_byte(expected).map_err(|_| error)
    }

    fn exact_u16(
        &mut self,
        expected: u16,
        error: RecipientKeyDescriptorErrorV1,
    ) -> Result<(), RecipientKeyDescriptorErrorV1> {
        self.exact_byte(0x18)
            .and_then(|()| self.exact_byte(expected.to_be_bytes()[1]))
            .map_err(|_| error)
    }

    fn owner(&mut self) -> Result<OwnerIdV1, RecipientKeyDescriptorErrorV1> {
        self.exact_byte(0x78)?;
        self.exact_byte(OWNER_LENGTH_U8)?;
        self.take(OWNER_LENGTH)
            .and_then(|bytes| {
                std::str::from_utf8(bytes).map_err(|_| RecipientKeyDescriptorErrorV1::InvalidOwner)
            })
            .and_then(|owner| {
                OwnerIdV1::new(owner).map_err(|_| RecipientKeyDescriptorErrorV1::InvalidOwner)
            })
            .and_then(|owner| {
                is_recipient_owner(&owner)
                    .then_some(owner)
                    .ok_or(RecipientKeyDescriptorErrorV1::InvalidOwner)
            })
    }

    fn unsigned(&mut self) -> Result<u64, RecipientKeyDescriptorErrorV1> {
        let first = self.next()?;
        match first {
            0..=23 => Ok(u64::from(first)),
            0x18 => self.next().and_then(|value| {
                (value >= 24)
                    .then_some(u64::from(value))
                    .ok_or(RecipientKeyDescriptorErrorV1::InvalidEncoding)
            }),
            0x19 => self.take(2).and_then(|bytes| {
                let value = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                (value > u64::from(u8::MAX))
                    .then_some(value)
                    .ok_or(RecipientKeyDescriptorErrorV1::InvalidEncoding)
            }),
            0x1a => self.take(4).and_then(|bytes| {
                let value = u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                (value > u64::from(u16::MAX))
                    .then_some(value)
                    .ok_or(RecipientKeyDescriptorErrorV1::InvalidEncoding)
            }),
            0x1b => self.take(8).and_then(|bytes| {
                let value = u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                (value > u64::from(u32::MAX))
                    .then_some(value)
                    .ok_or(RecipientKeyDescriptorErrorV1::InvalidEncoding)
            }),
            _ => Err(RecipientKeyDescriptorErrorV1::InvalidEncoding),
        }
    }

    fn public_key(&mut self) -> Result<[u8; 32], RecipientKeyDescriptorErrorV1> {
        self.exact_byte(0x58)?;
        self.exact_byte(32)?;
        self.take(32).and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|_| RecipientKeyDescriptorErrorV1::InvalidEncoding)
        })
    }

    fn exact_byte(&mut self, expected: u8) -> Result<(), RecipientKeyDescriptorErrorV1> {
        self.next().and_then(|actual| {
            (actual == expected)
                .then_some(())
                .ok_or(RecipientKeyDescriptorErrorV1::InvalidEncoding)
        })
    }

    fn next(&mut self) -> Result<u8, RecipientKeyDescriptorErrorV1> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RecipientKeyDescriptorErrorV1> {
        let end = self.position.saturating_add(length);
        let result = self
            .bytes
            .get(self.position..end)
            .ok_or(RecipientKeyDescriptorErrorV1::InvalidEncoding)?;
        self.position = end;
        Ok(result)
    }

    const fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn grantee() -> EntityId {
        EntityId::from_ulid(Ulid::from(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff_u128))
    }

    #[test]
    fn rkp1_has_exact_canonical_vector_and_fingerprint() -> Result<(), RecipientKeyDescriptorErrorV1>
    {
        let descriptor = RecipientKeyDescriptorV1::for_grantee(grantee(), 24, [0xab; 32])?;
        let expected = [
            0x87, 0x44, b'R', b'K', b'P', b'1', 0x01, 0x78, 0x2a, b'r', b'e', b'c', b'i', b'p',
            b'i', b'e', b'n', b't', b':', b'0', b'0', b'1', b'1', b'2', b'2', b'3', b'3', b'4',
            b'4', b'5', b'5', b'6', b'6', b'7', b'7', b'8', b'8', b'9', b'9', b'a', b'a', b'b',
            b'b', b'c', b'c', b'd', b'd', b'e', b'e', b'f', b'f', 0x04, 0x18, 0x18, 0x18, 0x20,
            0x58, 0x20,
        ];
        let mut expected = expected.to_vec();
        expected.extend_from_slice(&[0xab; 32]);
        assert_eq!(descriptor.encode(), expected);
        assert_eq!(RecipientKeyDescriptorV1::decode(&expected)?, descriptor);
        assert_eq!(
            descriptor.fingerprint(),
            Hash::from_bytes([
                0xaf, 0xf4, 0x3e, 0x79, 0xa7, 0xb4, 0x3d, 0x3b, 0x6c, 0xc5, 0x7d, 0xd9, 0x10, 0x21,
                0x0a, 0xc2, 0x4b, 0x8b, 0x61, 0x79, 0x14, 0x9e, 0x97, 0x23, 0xb4, 0xd5, 0xc5, 0x1d,
                0xb9, 0x7e, 0xf4, 0x09,
            ])
        );
        Ok(())
    }

    #[test]
    fn rkp1_rejects_noncanonical_and_unbound_owner_forms(
    ) -> Result<(), RecipientKeyDescriptorErrorV1> {
        let descriptor = RecipientKeyDescriptorV1::for_grantee(grantee(), 1, [7; 32])?;
        let mut noncanonical = descriptor.encode();
        noncanonical[52] = 0x18;
        noncanonical.insert(53, 1);
        assert_eq!(
            RecipientKeyDescriptorV1::decode(&noncanonical),
            Err(RecipientKeyDescriptorErrorV1::InvalidEncoding)
        );

        let mut owner = descriptor.encode();
        owner[10] = b'R';
        assert_eq!(
            RecipientKeyDescriptorV1::decode(&owner),
            Err(RecipientKeyDescriptorErrorV1::InvalidOwner)
        );
        assert!(descriptor.is_for_grantee(grantee()));
        assert!(!descriptor.is_for_grantee(EntityId::new()));
        Ok(())
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn rkp1_public_api_covers_all_canonical_epoch_widths_and_rejection_classes(
    ) -> Result<(), RecipientKeyDescriptorErrorV1> {
        let grantee = EntityId::from_ulid(ulid::Ulid::from(1));
        for epoch in [1, 24, 0x100, 0x1_0000, 0x1_0000_0000] {
            let descriptor = RecipientKeyDescriptorV1::for_grantee(grantee, epoch, [9; 32])?;
            assert_eq!(
                RecipientKeyDescriptorV1::decode(&descriptor.encode()),
                Ok(descriptor)
            );
        }
        assert_eq!(
            RecipientKeyDescriptorV1::for_grantee(grantee, 0, [0; 32]),
            Err(RecipientKeyDescriptorErrorV1::InvalidEpoch)
        );

        let valid = RecipientKeyDescriptorV1::for_grantee(grantee, 1, [9; 32])?.encode();
        for (offset, value, expected) in [
            (0, 0, RecipientKeyDescriptorErrorV1::InvalidEncoding),
            (6, 2, RecipientKeyDescriptorErrorV1::UnsupportedVersion),
            (51, 3, RecipientKeyDescriptorErrorV1::InvalidRole),
            (54, 0, RecipientKeyDescriptorErrorV1::InvalidKem),
        ] {
            let mut malformed = valid.clone();
            malformed[offset] = value;
            assert_eq!(RecipientKeyDescriptorV1::decode(&malformed), Err(expected));
        }
        let mut zero_epoch = valid.clone();
        zero_epoch[52] = 0;
        assert_eq!(
            RecipientKeyDescriptorV1::decode(&zero_epoch),
            Err(RecipientKeyDescriptorErrorV1::InvalidEpoch)
        );
        let mut non_unsigned_epoch = valid.clone();
        non_unsigned_epoch[52] = 0x1c;
        assert_eq!(
            RecipientKeyDescriptorV1::decode(&non_unsigned_epoch),
            Err(RecipientKeyDescriptorErrorV1::InvalidEncoding)
        );
        let mut invalid_owner = valid.clone();
        invalid_owner[10] = b'G';
        assert_eq!(
            RecipientKeyDescriptorV1::decode(&invalid_owner),
            Err(RecipientKeyDescriptorErrorV1::InvalidOwner)
        );
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            RecipientKeyDescriptorV1::decode(&trailing),
            Err(RecipientKeyDescriptorErrorV1::InvalidEncoding)
        );
        for length in 0..valid.len() {
            assert!(RecipientKeyDescriptorV1::decode(&valid[..length]).is_err());
        }
        Ok(())
    }
}
