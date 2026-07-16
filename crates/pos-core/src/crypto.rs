use serde::{Deserialize, Serialize};

/// A 32-byte cryptographic hash (e.g. BLAKE3-256). Algorithms live in pos-crypto.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash(#[serde(with = "bytes_32")] [u8; 32]);

impl Hash {
    #[must_use] 
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    #[must_use] 
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use] 
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }
}

/// An Ed25519 public key (32 bytes). Full algorithms in pos-crypto.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "bytes_32")] [u8; 32]);

impl PublicKey {
    #[must_use] 
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    #[must_use] 
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An Ed25519 signature (64 bytes). Full algorithms in pos-crypto.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "bytes_64")] [u8; 64]);

impl Signature {
    #[must_use] 
    pub const fn from_bytes(b: [u8; 64]) -> Self {
        Self(b)
    }

    #[must_use] 
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

mod bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v = serde_bytes::ByteBuf::deserialize(d)?;
        v.into_vec()
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v = serde_bytes::ByteBuf::deserialize(d)?;
        v.into_vec()
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_json_round_trip() {
        let h = Hash::from_bytes([42u8; 32]);
        let back: Hash = serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn hash_cbor_round_trip() {
        let h = Hash::from_bytes([0xABu8; 32]);
        let mut buf = Vec::new();
        ciborium::into_writer(&h, &mut buf).unwrap();
        let back: Hash = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn hash_zero() {
        assert_eq!(Hash::zero().as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn public_key_round_trip() {
        let pk = PublicKey::from_bytes([1u8; 32]);
        let back: PublicKey =
            serde_json::from_str(&serde_json::to_string(&pk).unwrap()).unwrap();
        assert_eq!(pk, back);
    }

    #[test]
    fn signature_round_trip() {
        let sig = Signature::from_bytes([7u8; 64]);
        let back: Signature =
            serde_json::from_str(&serde_json::to_string(&sig).unwrap()).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn signature_cbor_round_trip() {
        let sig = Signature::from_bytes([0xFFu8; 64]);
        let mut buf = Vec::new();
        ciborium::into_writer(&sig, &mut buf).unwrap();
        let back: Signature = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn hash_as_bytes_identity() {
        let raw = [5u8; 32];
        let h = Hash::from_bytes(raw);
        assert_eq!(h.as_bytes(), &raw);
    }

    #[test]
    fn hash_rejects_wrong_byte_length() {
        let mut buf = Vec::new();
        ciborium::into_writer(&[0u8; 16], &mut buf).unwrap();
        let result: Result<Hash, _> = ciborium::from_reader(buf.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn signature_rejects_wrong_byte_length() {
        let mut buf = Vec::new();
        ciborium::into_writer(&[0u8; 32], &mut buf).unwrap();
        let result: Result<Signature, _> = ciborium::from_reader(buf.as_slice());
        assert!(result.is_err());
    }
}
