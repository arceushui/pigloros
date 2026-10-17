use serde::{Deserialize, Serialize};

use crate::CanonicalLengthErrorV1;

/// A 32-byte cryptographic hash (e.g. BLAKE3-256). Algorithms live in pos-crypto.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

    pub(super) fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v = serde_bytes::ByteBuf::deserialize(d)?;
        v.into_vec()
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        serde_bytes::ByteBuf::deserialize(d).and_then(|v| {
            v.into_vec()
                .try_into()
                .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
        })
    }
}

// Private canonical native emission: one schema for buffers and checked lengths.
const _: () = assert!(usize::BITS <= u64::BITS);

pub(crate) trait CanonicalEmit {
    fn emit(&self, out: &mut impl CanonicalSink);
}

pub(crate) trait CanonicalSink {
    fn extend_from_slice(&mut self, bytes: &[u8]);

    fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    fn nested_byte_string(&mut self, value: &impl CanonicalEmit);
}

impl CanonicalSink for Vec<u8> {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Self::extend_from_slice(self, bytes);
    }

    fn nested_byte_string(&mut self, value: &impl CanonicalEmit) {
        let mut inner = Self::new();
        value.emit(&mut inner);
        bytes(self, &inner);
    }
}

struct LengthSink {
    length: Option<usize>,
    maximum: usize,
}

impl LengthSink {
    const fn new() -> Self {
        Self {
            length: Some(0),
            maximum: usize::MAX,
        }
    }

    fn add(&mut self, amount: usize) {
        self.length = self.length.and_then(|length| {
            length
                .checked_add(amount)
                .filter(|next| *next <= self.maximum)
        });
    }

    const fn finish(self) -> Result<usize, CanonicalLengthErrorV1> {
        match self.length {
            Some(length) => Ok(length),
            None => Err(CanonicalLengthErrorV1::LengthOverflow),
        }
    }
}

impl CanonicalSink for LengthSink {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        // Slice lengths already have the target's usize representation; no
        // wire integer is narrowed or interpreted as an allocated payload.
        self.add(bytes.len());
    }

    fn nested_byte_string(&mut self, value: &impl CanonicalEmit) {
        let start = self.length;
        value.emit(self);
        if let Some((end, start)) = self.length.zip(start) {
            // Counting is commutative: count the existing nested emitter first,
            // then its byte-string head. A successful counter is monotone.
            head(self, 2, (end - start) as u64);
        }
    }
}

pub(crate) fn measure(value: &impl CanonicalEmit) -> Result<usize, CanonicalLengthErrorV1> {
    let mut out = LengthSink::new();
    value.emit(&mut out);
    out.finish()
}

pub(crate) fn head(out: &mut impl CanonicalSink, major: u8, value: u64) {
    let tag = major << 5;
    // The major tag and additional-information field occupy disjoint bits.
    // Their sum is the CBOR prefix and cannot overflow a byte (224 + 31).
    if value < 24 {
        out.push(tag + value.to_be_bytes()[7]);
    } else if let Ok(value) = u8::try_from(value) {
        out.extend_from_slice(&[tag + 0x18, value]);
    } else if let Ok(value) = u16::try_from(value) {
        out.push(tag + 0x19);
        out.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        out.push(tag + 0x1a);
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.push(tag + 0x1b);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub(crate) fn bytes(out: &mut impl CanonicalSink, value: &[u8]) {
    head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

pub(crate) fn text(out: &mut impl CanonicalSink, value: &str) {
    head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod canonical_length_tests {
    use super::*;

    struct OneByte;

    impl CanonicalEmit for OneByte {
        fn emit(&self, out: &mut impl CanonicalSink) {
            out.push(1);
        }
    }

    #[test]
    fn checked_counter_accepts_exact_maximum_and_permanently_rejects_one_over() {
        let mut out = LengthSink::new();
        out.add(usize::MAX - 1);
        out.push(1);
        assert_eq!(out.finish(), Ok(usize::MAX));
        let mut out = LengthSink::new();
        out.add(usize::MAX);
        out.nested_byte_string(&OneByte);
        out.push(1);
        assert_eq!(out.finish(), Err(CanonicalLengthErrorV1::LengthOverflow));
    }

    #[test]
    fn nested_count_uses_the_same_emitter_without_materializing_a_buffer() {
        let mut bytes = Vec::new();
        bytes.nested_byte_string(&OneByte);
        let mut count = LengthSink::new();
        count.nested_byte_string(&OneByte);
        assert_eq!(bytes, [0x41, 1]);
        assert_eq!(count.finish(), Ok(bytes.len()));
    }

    #[test]
    fn the_actual_counting_primitive_enforces_a_32_bit_target_ceiling() {
        let maximum = u32::MAX as usize;
        let mut count = LengthSink {
            length: Some(maximum - 1),
            maximum,
        };
        count.push(1);
        assert_eq!(count.length, Some(maximum));
        count.push(1);
        assert_eq!(count.finish(), Err(CanonicalLengthErrorV1::LengthOverflow));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn hash_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let h = Hash::from_bytes([42u8; 32]);
        let back: Hash = serde_json::from_str(&serde_json::to_string(&h)?)?;
        assert_eq!(h, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn hash_cbor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let h = Hash::from_bytes([0xABu8; 32]);
        let mut buf = Vec::new();
        ciborium::into_writer(&h, &mut buf)?;
        let back: Hash = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(h, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn hash_zero() {
        assert_eq!(Hash::zero().as_bytes(), &[0u8; 32]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_key_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let pk = PublicKey::from_bytes([1u8; 32]);
        let back: PublicKey = serde_json::from_str(&serde_json::to_string(&pk)?)?;
        assert_eq!(pk, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signature_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let sig = Signature::from_bytes([7u8; 64]);
        let back: Signature = serde_json::from_str(&serde_json::to_string(&sig)?)?;
        assert_eq!(sig, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signature_cbor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let sig = Signature::from_bytes([0xFFu8; 64]);
        let mut buf = Vec::new();
        ciborium::into_writer(&sig, &mut buf)?;
        let back: Signature = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(sig, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn hash_as_bytes_identity() {
        let raw = [5u8; 32];
        let h = Hash::from_bytes(raw);
        assert_eq!(h.as_bytes(), &raw);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn hash_rejects_wrong_byte_length() -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(&[0u8; 16], &mut buf)?;
        let result: Result<Hash, _> = ciborium::from_reader(buf.as_slice());
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signature_rejects_wrong_byte_length() -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(&[0u8; 32], &mut buf)?;
        let result: Result<Signature, _> = ciborium::from_reader(buf.as_slice());
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn hash_rejects_non_bytes_json() {
        let result: Result<Hash, _> = serde_json::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signature_as_bytes_identity() {
        let raw = [7u8; 64];
        let s = Signature::from_bytes(raw);
        assert_eq!(s.as_bytes(), &raw);
    }
}
