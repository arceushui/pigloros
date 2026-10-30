//! DSSE (the in-toto Envelope) with exactly one Ed25519 signature over the PAE, as the ADR-062
//! Revision 8 report attestation uses it (section 5.1, slice G1, #1236).
//!
//! The envelope is the RFC 8785 canonical JSON object
//! `{"payload":…,"payloadType":…,"signatures":[{"keyid":…,"sig":…}]}`. `payload` and `sig` are
//! padded standard base64, and `keyid` is the lowercase hexadecimal BLAKE3 digest of the 32-byte
//! Ed25519 verifying key. The signature covers
//! `PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, with `LEN` the ASCII
//! decimal byte length. The reader is bounded before any allocation and accepts only the exact
//! canonical encoding of one single-signature envelope. The key id is an unauthenticated hint:
//! trust admission resolves it to a key, and [`DsseEnvelopeV1::verify`] checks that the key
//! matches it before verifying the signature.

use crate::jcs::JsonV1;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

/// The DSSE `payloadType` of an in-toto Statement.
pub const IN_TOTO_PAYLOAD_TYPE_V1: &str = "application/vnd.in-toto+json";

/// Why an envelope was refused by the bounded reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DsseParseErrorV1 {
    /// The envelope is longer than the caller's bound; nothing was parsed.
    #[error("DSSE envelope exceeds its byte bound")]
    Oversized,
    /// The envelope is not the canonical encoding of one single-signature envelope.
    #[error("DSSE envelope is not one canonical single-signature envelope")]
    Malformed,
}

/// Why an envelope signature was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DsseSignatureErrorV1 {
    /// The key id is not the BLAKE3 digest of the verifying key.
    #[error("DSSE key id does not name the verifying key")]
    KeyIdMismatch,
    /// The signature does not verify over the PAE.
    #[error("DSSE signature does not verify over the PAE")]
    InvalidSignature,
}

/// The DSSE pre-authentication encoding of `payload` under `payload_type`.
#[must_use]
pub fn pae_v1(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// The key id of `key`: the BLAKE3 digest of its 32 bytes.
#[must_use]
pub fn key_id_v1(key: &VerifyingKey) -> [u8; 32] {
    *blake3::hash(key.as_bytes()).as_bytes()
}

/// One DSSE envelope with exactly one signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DsseEnvelopeV1 {
    payload_type: String,
    payload: Vec<u8>,
    key_id: [u8; 32],
    signature: [u8; 64],
}

impl DsseEnvelopeV1 {
    /// Sign `payload` under `payload_type` with `key`.
    #[must_use]
    pub fn sign(payload_type: &str, payload: Vec<u8>, key: &SigningKey) -> Self {
        let signature = key.sign(&pae_v1(payload_type, &payload)).to_bytes();
        Self {
            payload_type: payload_type.to_owned(),
            payload,
            key_id: key_id_v1(&key.verifying_key()),
            signature,
        }
    }

    /// The canonical JSON bytes of the envelope.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        JsonV1::object([
            ("payload", JsonV1::Text(STANDARD.encode(&self.payload))),
            ("payloadType", JsonV1::text(&self.payload_type)),
            (
                "signatures",
                JsonV1::Array(vec![JsonV1::object([
                    (
                        "keyid",
                        JsonV1::Text(blake3::Hash::from_bytes(self.key_id).to_hex().to_string()),
                    ),
                    ("sig", JsonV1::Text(STANDARD.encode(self.signature))),
                ])]),
            ),
        ])
        .canonical()
    }

    /// Read one canonical envelope of at most `max_bytes` bytes.
    ///
    /// # Errors
    /// Returns [`DsseParseErrorV1::Oversized`] before parsing when `bytes` is longer than
    /// `max_bytes`, and [`DsseParseErrorV1::Malformed`] for any other envelope that is not the
    /// exact canonical encoding of one single-signature envelope.
    pub fn from_json(bytes: &[u8], max_bytes: usize) -> Result<Self, DsseParseErrorV1> {
        if bytes.len() > max_bytes {
            return Err(DsseParseErrorV1::Oversized);
        }
        JsonV1::parse_canonical(bytes)
            .and_then(Self::from_value)
            .filter(|envelope| envelope.to_json() == bytes)
            .ok_or(DsseParseErrorV1::Malformed)
    }

    fn from_value(value: JsonV1) -> Option<Self> {
        let [payload, payload_type, signatures] =
            value.into_members(["payload", "payloadType", "signatures"])?;
        let [signature]: [JsonV1; 1] = signatures.into_array()?.try_into().ok()?;
        let [key_id, signature] = signature.into_members(["keyid", "sig"])?;
        Some(Self {
            payload_type: payload_type.into_text()?,
            payload: decode_base64(payload)?,
            key_id: *blake3::Hash::from_hex(key_id.into_text()?).ok()?.as_bytes(),
            signature: decode_base64(signature)?.try_into().ok()?,
        })
    }

    /// Whether the envelope's `payloadType` is exactly `payload_type`.
    #[must_use]
    pub fn has_payload_type(&self, payload_type: &str) -> bool {
        self.payload_type == payload_type
    }

    /// The signed payload bytes.
    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// The key id the envelope names.
    #[must_use]
    pub const fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    /// Verify the signature with `key`, which must be the key the key id names.
    ///
    /// # Errors
    /// Returns [`DsseSignatureErrorV1::KeyIdMismatch`] when the key id is not the BLAKE3 digest
    /// of `key`, and [`DsseSignatureErrorV1::InvalidSignature`] when the signature does not
    /// verify strictly over the PAE.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), DsseSignatureErrorV1> {
        if key_id_v1(key) != self.key_id {
            return Err(DsseSignatureErrorV1::KeyIdMismatch);
        }
        key.verify_strict(
            &pae_v1(&self.payload_type, &self.payload),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| DsseSignatureErrorV1::InvalidSignature)
    }
}

fn decode_base64(value: JsonV1) -> Option<Vec<u8>> {
    value
        .into_text()
        .and_then(|text| STANDARD.decode(text).ok())
}
