//! Durable Fork-admission bootstrap records from ADR-106.
//!
//! These strict codecs describe bootstrap and open proofs. They do not grant
//! authority: the store must verify the corresponding host signature and bind
//! the resulting state to its own one-use challenge lifecycle.

use std::io::Cursor;

use ciborium::value::Value;

use crate::{Hash, PublicKey};

/// Exact complete FAH1 record size.
pub const MAX_FORK_ADMISSION_HOST_RECORD_BYTES_V1: usize = 109;
/// Exact complete FAI1 challenge size.
pub const MAX_FORK_ADMISSION_INITIALIZE_CHALLENGE_BYTES_V1: usize = 143;
/// Exact complete FAO1 challenge size.
pub const MAX_FORK_ADMISSION_OPEN_CHALLENGE_BYTES_V1: usize = 109;

/// Closed failures for ADR-106 durable authority codecs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAdmissionAuthorityCodecErrorV1 {
    #[error("Fork-admission authority encoding is invalid")]
    InvalidEncoding,
    #[error("Fork-admission authority version is unsupported")]
    UnsupportedVersion,
    #[error("Fork-admission authority field is out of bounds")]
    FieldOutOfBounds,
}

/// The one immutable FAH1 authority identity persisted by an initialized store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkAdmissionHostRecordV1 {
    store_id: Hash,
    host_verifying_key: PublicKey,
    authentication_policy_digest: Hash,
}

impl ForkAdmissionHostRecordV1 {
    /// Construct FAH1 from a successful FAI1 finalize result.
    ///
    /// Construction validates only record shape. A store accepts this record
    /// only after verifying an exact one-use FAI1 proof in its transaction.
    ///
    /// # Errors
    /// Returns an error for a zero store identity, key, or policy digest.
    pub fn new(
        store_id: Hash,
        host_verifying_key: PublicKey,
        authentication_policy_digest: Hash,
    ) -> Result<Self, ForkAdmissionAuthorityCodecErrorV1> {
        let record = Self {
            store_id,
            host_verifying_key,
            authentication_policy_digest,
        };
        record.validate()?;
        Ok(record)
    }

    /// Decode exact deterministic-CBOR FAH1 bytes.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, unsupported, or unbounded bytes.
    pub fn from_canonical_cbor(
        bytes_in: &[u8],
    ) -> Result<Self, ForkAdmissionAuthorityCodecErrorV1> {
        let fields = decode(bytes_in, MAX_FORK_ADMISSION_HOST_RECORD_BYTES_V1, 5, "FAH1")?;
        Ok(Self {
            store_id: Hash::from_bytes(fixed_nonzero(&fields[2])?),
            host_verifying_key: PublicKey::from_bytes(fixed_nonzero(&fields[3])?),
            authentication_policy_digest: Hash::from_bytes(fixed_nonzero(&fields[4])?),
        })
    }

    /// Encode exact deterministic-CBOR FAH1 bytes; identical to `canonical_bytes`.
    ///
    /// # Errors
    /// Never returns an error: the closed encoder is infallible. The `Result`
    /// only keeps the shared `to_canonical_cbor` codec shape.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ForkAdmissionAuthorityCodecErrorV1> {
        Ok(self.canonical_bytes())
    }

    /// Return the exact deterministic-CBOR FAH1 bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode(
            0x85,
            *b"FAH1",
            &[
                self.store_id.as_bytes(),
                self.host_verifying_key.as_bytes(),
                self.authentication_policy_digest.as_bytes(),
            ],
        )
    }

    #[must_use]
    pub const fn store_id(&self) -> Hash {
        self.store_id
    }

    #[must_use]
    pub const fn host_verifying_key(&self) -> PublicKey {
        self.host_verifying_key
    }

    #[must_use]
    pub const fn authentication_policy_digest(&self) -> Hash {
        self.authentication_policy_digest
    }

    fn validate(&self) -> Result<(), ForkAdmissionAuthorityCodecErrorV1> {
        require_nonzero(&[
            self.store_id.as_bytes(),
            self.host_verifying_key.as_bytes(),
            self.authentication_policy_digest.as_bytes(),
        ])
    }
}

/// One adapter-instance-bound, one-use FAI1 initialization challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkAdmissionInitializeChallengeV1 {
    store_id: Hash,
    initialization_nonce: Hash,
    host_verifying_key: PublicKey,
    authentication_policy_digest: Hash,
}

impl ForkAdmissionInitializeChallengeV1 {
    /// Construct FAI1 from store-generated entropy and deployment policy.
    ///
    /// # Errors
    /// Returns an error for a zero identity, nonce, key, or policy digest.
    pub fn new(
        store_id: Hash,
        initialization_nonce: Hash,
        host_verifying_key: PublicKey,
        authentication_policy_digest: Hash,
    ) -> Result<Self, ForkAdmissionAuthorityCodecErrorV1> {
        let challenge = Self {
            store_id,
            initialization_nonce,
            host_verifying_key,
            authentication_policy_digest,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    /// Decode exact deterministic-CBOR FAI1 bytes.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, unsupported, or unbounded bytes.
    pub fn from_canonical_cbor(
        bytes_in: &[u8],
    ) -> Result<Self, ForkAdmissionAuthorityCodecErrorV1> {
        let fields = decode(
            bytes_in,
            MAX_FORK_ADMISSION_INITIALIZE_CHALLENGE_BYTES_V1,
            6,
            "FAI1",
        )?;
        Ok(Self {
            store_id: Hash::from_bytes(fixed_nonzero(&fields[2])?),
            initialization_nonce: Hash::from_bytes(fixed_nonzero(&fields[3])?),
            host_verifying_key: PublicKey::from_bytes(fixed_nonzero(&fields[4])?),
            authentication_policy_digest: Hash::from_bytes(fixed_nonzero(&fields[5])?),
        })
    }

    /// Encode exact deterministic-CBOR FAI1 bytes; identical to `canonical_bytes`.
    ///
    /// # Errors
    /// Never returns an error: the closed encoder is infallible. The `Result`
    /// only keeps the shared `to_canonical_cbor` codec shape.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ForkAdmissionAuthorityCodecErrorV1> {
        Ok(self.canonical_bytes())
    }

    /// Return the exact deterministic-CBOR FAI1 bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode(
            0x86,
            *b"FAI1",
            &[
                self.store_id.as_bytes(),
                self.initialization_nonce.as_bytes(),
                self.host_verifying_key.as_bytes(),
                self.authentication_policy_digest.as_bytes(),
            ],
        )
    }

    #[must_use]
    pub const fn store_id(&self) -> Hash {
        self.store_id
    }

    #[must_use]
    pub const fn initialization_nonce(&self) -> Hash {
        self.initialization_nonce
    }

    #[must_use]
    pub const fn host_verifying_key(&self) -> PublicKey {
        self.host_verifying_key
    }

    #[must_use]
    pub const fn authentication_policy_digest(&self) -> Hash {
        self.authentication_policy_digest
    }

    /// Return the FAH1 fields that this FAI1 carries.
    ///
    /// This preserves record shape only. The store must verify the FAI1
    /// signature and consume the one-use challenge before persisting FAH1.
    #[must_use]
    pub const fn host_record(&self) -> ForkAdmissionHostRecordV1 {
        ForkAdmissionHostRecordV1 {
            store_id: self.store_id,
            host_verifying_key: self.host_verifying_key,
            authentication_policy_digest: self.authentication_policy_digest,
        }
    }

    fn validate(&self) -> Result<(), ForkAdmissionAuthorityCodecErrorV1> {
        require_nonzero(&[
            self.store_id.as_bytes(),
            self.initialization_nonce.as_bytes(),
            self.host_verifying_key.as_bytes(),
            self.authentication_policy_digest.as_bytes(),
        ])
    }
}

/// One adapter-instance-bound, one-use FAO1 authority-open challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkAdmissionOpenChallengeV1 {
    store_id: Hash,
    open_nonce: Hash,
    authentication_policy_digest: Hash,
}

impl ForkAdmissionOpenChallengeV1 {
    /// Construct FAO1 from a persisted FAH1 identity and store-generated entropy.
    ///
    /// # Errors
    /// Returns an error for a zero identity, nonce, or policy digest.
    pub fn new(
        store_id: Hash,
        open_nonce: Hash,
        authentication_policy_digest: Hash,
    ) -> Result<Self, ForkAdmissionAuthorityCodecErrorV1> {
        let challenge = Self {
            store_id,
            open_nonce,
            authentication_policy_digest,
        };
        require_nonzero(&[
            challenge.store_id.as_bytes(),
            challenge.open_nonce.as_bytes(),
            challenge.authentication_policy_digest.as_bytes(),
        ])
        .map(|()| challenge)
    }

    /// Decode exact deterministic-CBOR FAO1 bytes.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, unsupported, or unbounded bytes.
    pub fn from_canonical_cbor(
        bytes_in: &[u8],
    ) -> Result<Self, ForkAdmissionAuthorityCodecErrorV1> {
        let fields = decode(
            bytes_in,
            MAX_FORK_ADMISSION_OPEN_CHALLENGE_BYTES_V1,
            5,
            "FAO1",
        )?;
        Ok(Self {
            store_id: Hash::from_bytes(fixed_nonzero(&fields[2])?),
            open_nonce: Hash::from_bytes(fixed_nonzero(&fields[3])?),
            authentication_policy_digest: Hash::from_bytes(fixed_nonzero(&fields[4])?),
        })
    }

    /// Encode exact deterministic-CBOR FAO1 bytes; identical to `canonical_bytes`.
    ///
    /// # Errors
    /// Never returns an error: the closed encoder is infallible. The `Result`
    /// only keeps the shared `to_canonical_cbor` codec shape.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ForkAdmissionAuthorityCodecErrorV1> {
        Ok(self.canonical_bytes())
    }

    /// Return the exact deterministic-CBOR FAO1 bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode(
            0x85,
            *b"FAO1",
            &[
                self.store_id.as_bytes(),
                self.open_nonce.as_bytes(),
                self.authentication_policy_digest.as_bytes(),
            ],
        )
    }

    #[must_use]
    pub const fn store_id(&self) -> Hash {
        self.store_id
    }

    #[must_use]
    pub const fn open_nonce(&self) -> Hash {
        self.open_nonce
    }

    #[must_use]
    pub const fn authentication_policy_digest(&self) -> Hash {
        self.authentication_policy_digest
    }
}

fn decode(
    bytes_in: &[u8],
    maximum: usize,
    fields: usize,
    marker: &str,
) -> Result<Vec<Value>, ForkAdmissionAuthorityCodecErrorV1> {
    // Each accepted field has a fixed shortest encoding. A nonshortest form
    // exceeds the exact complete-record ceiling before it can be accepted.
    if bytes_in.len() > maximum {
        return Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds);
    }
    let mut cursor = Cursor::new(bytes_in);
    let value: Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)?;
    if cursor.position() != bytes_in.len() as u64 {
        return Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding);
    }
    let Value::Array(values) = value else {
        return Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding);
    };
    if values.len() != fields
        || !matches!(values.first(), Some(Value::Text(value)) if value == marker)
    {
        return Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding);
    }
    match values.get(1) {
        Some(Value::Integer(value)) if *value == 1.into() => Ok(values),
        Some(Value::Integer(_)) => Err(ForkAdmissionAuthorityCodecErrorV1::UnsupportedVersion),
        _ => Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding),
    }
}

/// Reject any all-zero 32-byte identity, nonce, key, or digest field.
fn require_nonzero(fields: &[&[u8; 32]]) -> Result<(), ForkAdmissionAuthorityCodecErrorV1> {
    if fields.iter().any(|field| **field == [0; 32]) {
        Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn fixed_nonzero(value: &Value) -> Result<[u8; 32], ForkAdmissionAuthorityCodecErrorV1> {
    match value {
        Value::Bytes(value) if value.len() == 32 => {
            let mut bytes = [0; 32];
            bytes.copy_from_slice(value);
            if bytes == [0; 32] {
                Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
            } else {
                Ok(bytes)
            }
        }
        _ => Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds),
    }
}

fn encode(array_header: u8, marker: [u8; 4], fields: &[&[u8; 32]]) -> Vec<u8> {
    let mut output = Vec::with_capacity(7 + fields.len() * 34);
    output.push(array_header);
    output.push(0x64);
    output.extend_from_slice(&marker);
    output.push(1);
    for field in fields {
        output.extend_from_slice(&[0x58, 32]);
        output.extend_from_slice(*field);
    }
    output
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;

    use sha2::{Digest, Sha256};

    use super::{
        ForkAdmissionAuthorityCodecErrorV1, ForkAdmissionHostRecordV1,
        ForkAdmissionInitializeChallengeV1, ForkAdmissionOpenChallengeV1,
        MAX_FORK_ADMISSION_HOST_RECORD_BYTES_V1, MAX_FORK_ADMISSION_INITIALIZE_CHALLENGE_BYTES_V1,
        MAX_FORK_ADMISSION_OPEN_CHALLENGE_BYTES_V1,
    };
    use crate::{Hash, PublicKey};

    fn hash(value: u8) -> Hash {
        Hash::from_bytes([value; 32])
    }
    fn key(value: u8) -> PublicKey {
        PublicKey::from_bytes([value; 32])
    }

    fn hex_bytes<const N: usize>(source: &str) -> Result<[u8; N], Box<dyn Error>> {
        assert_eq!(source.len(), N * 2);
        let mut output = [0; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&source[index * 2..index * 2 + 2], 16)?;
        }
        Ok(output)
    }

    #[test]
    fn host_record_round_trip_and_rejects_bad_forms() -> Result<(), Box<dyn Error>> {
        let record = ForkAdmissionHostRecordV1::new(hash(1), key(2), hash(3))?;
        let bytes = record.to_canonical_cbor()?;
        assert_eq!(bytes.len(), MAX_FORK_ADMISSION_HOST_RECORD_BYTES_V1);
        assert_eq!(
            &bytes[..8],
            &[0x85, 0x64, b'F', b'A', b'H', b'1', 0x01, 0x58]
        );
        assert_eq!(
            &Sha256::digest(&bytes)[..],
            &hex_bytes::<32>("e4bae4c60a40fa77470f21fbf124ad4111241407219323e1cebd8ac2b67ac4da")?
        );
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(&bytes),
            Ok(record)
        );
        let mut noncanonical = bytes.clone();
        noncanonical[6] = 0x18;
        noncanonical.insert(7, 1);
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(&noncanonical),
            Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(&bytes[..bytes.len() - 1]),
            Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)
        );
        assert_eq!(
            ForkAdmissionHostRecordV1::new(Hash::zero(), key(2), hash(3)),
            Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(
                &[0; MAX_FORK_ADMISSION_HOST_RECORD_BYTES_V1 + 1]
            ),
            Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
        );
        Ok(())
    }

    #[test]
    fn initialize_challenge_round_trip_and_requires_every_nonzero_field(
    ) -> Result<(), Box<dyn Error>> {
        let challenge = ForkAdmissionInitializeChallengeV1::new(hash(1), hash(2), key(3), hash(4))?;
        let bytes = challenge.to_canonical_cbor()?;
        assert_eq!(
            bytes.len(),
            MAX_FORK_ADMISSION_INITIALIZE_CHALLENGE_BYTES_V1
        );
        assert_eq!(
            &bytes[..8],
            &[0x86, 0x64, b'F', b'A', b'I', b'1', 0x01, 0x58]
        );
        assert_eq!(
            &Sha256::digest(&bytes)[..],
            &hex_bytes::<32>("15880790f19369f735f6e1affa796b7f730fc756b1b546ac9bd5acc9471a1dee")?
        );
        assert_eq!(
            ForkAdmissionInitializeChallengeV1::from_canonical_cbor(&bytes),
            Ok(challenge)
        );
        assert_eq!(
            ForkAdmissionInitializeChallengeV1::new(hash(1), Hash::zero(), key(3), hash(4)),
            Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
        );
        let mut unsupported = bytes;
        unsupported[6] = 2;
        assert_eq!(
            ForkAdmissionInitializeChallengeV1::from_canonical_cbor(&unsupported),
            Err(ForkAdmissionAuthorityCodecErrorV1::UnsupportedVersion)
        );
        Ok(())
    }

    #[test]
    fn open_challenge_round_trip_and_rejects_trailing_bytes() -> Result<(), Box<dyn Error>> {
        let challenge = ForkAdmissionOpenChallengeV1::new(hash(1), hash(2), hash(3))?;
        let bytes = challenge.to_canonical_cbor()?;
        assert_eq!(bytes.len(), MAX_FORK_ADMISSION_OPEN_CHALLENGE_BYTES_V1);
        assert_eq!(
            &bytes[..8],
            &[0x85, 0x64, b'F', b'A', b'O', b'1', 0x01, 0x58]
        );
        assert_eq!(
            &Sha256::digest(&bytes)[..],
            &hex_bytes::<32>("c3c910fb0750922f6c5f5909aa1980353700ce7ed6640bbd5aa2b228aa898a91")?
        );
        assert_eq!(
            ForkAdmissionOpenChallengeV1::from_canonical_cbor(&bytes),
            Ok(challenge)
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            ForkAdmissionOpenChallengeV1::from_canonical_cbor(&trailing),
            Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
        );
        Ok(())
    }

    #[test]
    fn decoders_reject_wrong_shape_marker_version_and_zero_fields() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(&[0x80]),
            Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)
        );
        let record = ForkAdmissionHostRecordV1::new(hash(1), key(2), hash(3))?;
        let mut wrong_marker = record.to_canonical_cbor()?;
        wrong_marker[2] = b'X';
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(&wrong_marker),
            Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)
        );
        let mut wrong_version = record.to_canonical_cbor()?;
        wrong_version[6] = 2;
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(&wrong_version),
            Err(ForkAdmissionAuthorityCodecErrorV1::UnsupportedVersion)
        );
        let mut zero_field = record.to_canonical_cbor()?;
        zero_field[9..41].fill(0);
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(&zero_field),
            Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
        );
        Ok(())
    }
}
