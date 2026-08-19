//! Consent, revocation, and key-lifecycle CBOR codecs (ADR-039).
//!
//! Owns event types `"consent.granted.v1"` and `"consent.revoked.v1"`.
//! These event types are **Gateway-only** per ADR-024 section 2 - no Plugin may
//! propose or observe consent events directly.

use std::io::Cursor;

use ciborium::Value;

use crate::{event::CanonicalBytes, ids::EntityId};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Versioned event type for consent grants (ADR-039).
pub const EVENT_TYPE_CONSENT_GRANTED_V1: &str = "consent.granted.v1";

/// Versioned event type for consent revocations (ADR-039).
pub const EVENT_TYPE_CONSENT_REVOKED_V1: &str = "consent.revoked.v1";

const MAGIC_CGR1: &[u8; 4] = b"CGR1";
const MAGIC_CRV1: &[u8; 4] = b"CRV1";
const VERSION_V1: u8 = 1;

/// Maximum bytes for the `modalities` field in `ConsentGrantedV1`.
pub const MAX_MODALITIES_BYTES: usize = 256;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by consent CBOR codec operations.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum ConsentCodecError {
    #[error("wrong magic bytes")]
    WrongMagic,
    #[error("wrong schema version")]
    WrongVersion,
    #[error("wrong CBOR array length")]
    WrongArrayLength,
    #[error("wrong field type")]
    WrongFieldType,
    #[error("modalities payload too large: {size} bytes (max {MAX_MODALITIES_BYTES})")]
    ModalitiesTooLarge { size: usize },
    #[error("trailing bytes after CBOR item")]
    TrailingBytes,
    #[error("CBOR decode error")]
    CborError,
}

// ---------------------------------------------------------------------------
// CBOR helpers (private)
// ---------------------------------------------------------------------------

fn cbor_magic(magic: &[u8; 4]) -> Value {
    Value::Bytes(magic.to_vec())
}

fn cbor_u8(v: u8) -> Value {
    Value::Integer(ciborium::value::Integer::from(v))
}

fn cbor_u64(v: u64) -> Value {
    Value::Integer(ciborium::value::Integer::from(v))
}

fn cbor_bool(v: bool) -> Value {
    Value::Bool(v)
}

fn cbor_id(id: EntityId) -> Value {
    let n: u128 = id.inner().into();
    Value::Bytes(n.to_be_bytes().to_vec())
}

fn cbor_bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn cbor_encode(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("Vec<u8> write is infallible");
    buf
}

fn decode_array(bytes: &[u8], expected_len: usize) -> Result<Vec<Value>, ConsentCodecError> {
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::from_reader(&mut cursor).map_err(|_| ConsentCodecError::CborError)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ConsentCodecError::TrailingBytes);
    }
    match value {
        Value::Array(items) if items.len() == expected_len => Ok(items),
        Value::Array(_) => Err(ConsentCodecError::WrongArrayLength),
        _ => Err(ConsentCodecError::CborError),
    }
}

fn decode_magic(val: &Value, expected: &[u8; 4]) -> Result<(), ConsentCodecError> {
    match val {
        Value::Bytes(b) if b.as_slice() == expected => Ok(()),
        _ => Err(ConsentCodecError::WrongMagic),
    }
}

fn decode_version(val: &Value) -> Result<(), ConsentCodecError> {
    match val {
        Value::Integer(n) if u8::try_from(*n).ok() == Some(VERSION_V1) => Ok(()),
        _ => Err(ConsentCodecError::WrongVersion),
    }
}

fn decode_u8(val: &Value) -> Result<u8, ConsentCodecError> {
    match val {
        Value::Integer(n) => u8::try_from(*n).map_err(|_| ConsentCodecError::WrongFieldType),
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

fn decode_u64(val: &Value) -> Result<u64, ConsentCodecError> {
    match val {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| ConsentCodecError::WrongFieldType),
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

fn decode_bool(val: &Value) -> Result<bool, ConsentCodecError> {
    match val {
        Value::Bool(b) => Ok(*b),
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

fn decode_id(val: &Value) -> Result<EntityId, ConsentCodecError> {
    match val {
        Value::Bytes(b) if b.len() == 16 => {
            let arr: [u8; 16] = b.as_slice().try_into().expect("length checked above");
            let n = u128::from_be_bytes(arr);
            Ok(EntityId::from_ulid(ulid::Ulid::from(n)))
        }
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

fn decode_fixed32(val: &Value) -> Result<[u8; 32], ConsentCodecError> {
    match val {
        Value::Bytes(b) if b.len() == 32 => {
            Ok(b.as_slice().try_into().expect("length checked above"))
        }
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

fn decode_bytes_max(val: &Value, max: usize) -> Result<Vec<u8>, ConsentCodecError> {
    match val {
        Value::Bytes(b) => {
            if b.len() > max {
                Err(ConsentCodecError::ModalitiesTooLarge { size: b.len() })
            } else {
                Ok(b.clone())
            }
        }
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

// ---------------------------------------------------------------------------
// ConsentGrantedV1
// ---------------------------------------------------------------------------

/// A consent grant event (ADR-039, `consent.granted.v1`).
///
/// Array (11 elements):
/// `[magic_bstr4, version_u8=1, subject_id_bstr16, grantee_id_bstr16,
///   purpose_u8, modalities_bstr_max256, min_geo_resolution_u8,
///   export_allowed_bool, key_id_bstr32, granted_at_u64, expires_at]`
///
/// `expires_at`: `[0]` = absent, `[1, u64]` = present.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsentGrantedV1 {
    pub subject_id: EntityId,
    pub grantee_id: EntityId,
    pub purpose: u8,
    pub modalities: Vec<u8>,
    pub min_geo_resolution: u8,
    pub export_allowed: bool,
    pub key_id: [u8; 32],
    pub granted_at: u64,
    pub expires_at: Option<u64>,
}

impl ConsentGrantedV1 {
    /// Encode to canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns [`ConsentCodecError::ModalitiesTooLarge`] if `modalities` exceeds 256 bytes.
    pub fn encode(&self) -> Result<CanonicalBytes, ConsentCodecError> {
        if self.modalities.len() > MAX_MODALITIES_BYTES {
            return Err(ConsentCodecError::ModalitiesTooLarge {
                size: self.modalities.len(),
            });
        }
        let expires = match self.expires_at {
            None => Value::Array(vec![cbor_u8(0)]),
            Some(ts) => Value::Array(vec![cbor_u8(1), cbor_u64(ts)]),
        };
        let arr = Value::Array(vec![
            cbor_magic(MAGIC_CGR1),
            cbor_u8(VERSION_V1),
            cbor_id(self.subject_id),
            cbor_id(self.grantee_id),
            cbor_u8(self.purpose),
            cbor_bytes(&self.modalities),
            cbor_u8(self.min_geo_resolution),
            cbor_bool(self.export_allowed),
            cbor_bytes(&self.key_id),
            cbor_u64(self.granted_at),
            expires,
        ]);
        Ok(CanonicalBytes::from_vec(cbor_encode(&arr)))
    }

    /// Decode from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns a [`ConsentCodecError`] on any malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, ConsentCodecError> {
        let items = decode_array(bytes.as_slice(), 11)?;
        decode_magic(&items[0], MAGIC_CGR1)?;
        decode_version(&items[1])?;
        let subject_id = decode_id(&items[2])?;
        let grantee_id = decode_id(&items[3])?;
        let purpose = decode_u8(&items[4])?;
        let modalities = decode_bytes_max(&items[5], MAX_MODALITIES_BYTES)?;
        let min_geo_resolution = decode_u8(&items[6])?;
        let export_allowed = decode_bool(&items[7])?;
        let key_id = decode_fixed32(&items[8])?;
        let granted_at = decode_u64(&items[9])?;
        let expires_at = match &items[10] {
            Value::Array(v) if v.len() == 1 => {
                if decode_u8(&v[0])? != 0 {
                    return Err(ConsentCodecError::WrongFieldType);
                }
                None
            }
            Value::Array(v) if v.len() == 2 => {
                if decode_u8(&v[0])? != 1 {
                    return Err(ConsentCodecError::WrongFieldType);
                }
                Some(decode_u64(&v[1])?)
            }
            _ => return Err(ConsentCodecError::WrongFieldType),
        };
        Ok(Self {
            subject_id,
            grantee_id,
            purpose,
            modalities,
            min_geo_resolution,
            export_allowed,
            key_id,
            granted_at,
            expires_at,
        })
    }
}

// ---------------------------------------------------------------------------
// ConsentRevokedV1
// ---------------------------------------------------------------------------

/// A consent revocation event (ADR-039, `consent.revoked.v1`).
///
/// Array (6 elements):
/// `[magic_bstr4, version_u8=1, subject_id_bstr16, key_id_bstr32, revoked_at_u64, reason_u8]`
#[derive(Debug, Clone, PartialEq)]
pub struct ConsentRevokedV1 {
    pub subject_id: EntityId,
    pub key_id: [u8; 32],
    pub revoked_at: u64,
    pub reason: u8,
}

impl ConsentRevokedV1 {
    /// Encode to canonical CBOR bytes.
    ///
    /// # Errors
    /// This function is currently infallible but returns `Result` for API consistency.
    pub fn encode(&self) -> Result<CanonicalBytes, ConsentCodecError> {
        let arr = Value::Array(vec![
            cbor_magic(MAGIC_CRV1),
            cbor_u8(VERSION_V1),
            cbor_id(self.subject_id),
            cbor_bytes(&self.key_id),
            cbor_u64(self.revoked_at),
            cbor_u8(self.reason),
        ]);
        Ok(CanonicalBytes::from_vec(cbor_encode(&arr)))
    }

    /// Decode from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns a [`ConsentCodecError`] on any malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, ConsentCodecError> {
        let items = decode_array(bytes.as_slice(), 6)?;
        decode_magic(&items[0], MAGIC_CRV1)?;
        decode_version(&items[1])?;
        let subject_id = decode_id(&items[2])?;
        let key_id = decode_fixed32(&items[3])?;
        let revoked_at = decode_u64(&items[4])?;
        let reason = decode_u8(&items[5])?;
        Ok(Self {
            subject_id,
            key_id,
            revoked_at,
            reason,
        })
    }
}

// ---------------------------------------------------------------------------
// ConsentGate - plugin seam (ADR-039 section: plugin bypass mitigation)
// ---------------------------------------------------------------------------

/// Opaque token proving consent was checked for a given subject + event type.
///
/// Only `ConsentGate::check_consent` can produce this token. Callers must
/// present it to write sensitive event types on a subject's Timeline.
#[derive(Debug)]
pub struct ConsentCapabilityToken(());

impl ConsentCapabilityToken {
    /// Construct a token. Only callable within this module.
    pub(crate) fn new() -> Self {
        Self(())
    }
}

/// Errors returned by `ConsentGate::check_consent`.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum ConsentError {
    #[error("no active consent grant for this subject and event type")]
    NoConsent,
    #[error("consent has been revoked")]
    Revoked,
    #[error("consent grant has expired")]
    Expired,
    /// `consent.*` event types are Gateway-only per ADR-024 section2.
    #[error("consent.* event types are Gateway-only and cannot be accessed by plugins")]
    ConsentEventsForbidden,
}

/// Plugin seam for consent enforcement (ADR-039).
///
/// Equivalent to `GeoLocationAdmissionStore` - prevents plugins from
/// accessing sensitive event types without a valid consent grant.
pub trait ConsentGate: Send + Sync {
    /// Check whether `subject` holds an active, non-revoked consent grant
    /// that covers `event_type`.
    ///
    /// Returns [`ConsentCapabilityToken`] on success.
    /// Returns [`ConsentError::ConsentEventsForbidden`] if `event_type`
    /// starts with `"consent."` (Gateway-only, no plugin access allowed).
    ///
    /// # Errors
    /// Returns a [`ConsentError`] describing why consent was not granted.
    fn check_consent(
        &self,
        subject: EntityId,
        event_type: &crate::event::Kind,
    ) -> Result<ConsentCapabilityToken, ConsentError>;
}

// ---------------------------------------------------------------------------
// FieldState - Replay sentinel for destroyed keys (ADR-039)
// ---------------------------------------------------------------------------

/// State of a sensitive field when replaying after key destruction.
///
/// When a subject's data key is destroyed on revocation, Replay returns
/// `FieldState::RedactedDestroyed` for encrypted fields - not an error,
/// not null - so Replay remains deterministic.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldState {
    /// The field is present and decryptable.
    Present(CanonicalBytes),
    /// The field's encryption key has been destroyed; content is unavailable.
    RedactedDestroyed,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{event::Kind, ids::EntityId};

    fn sample_granted() -> ConsentGrantedV1 {
        ConsentGrantedV1 {
            subject_id: EntityId::new(),
            grantee_id: EntityId::new(),
            purpose: 1,
            modalities: vec![0x01, 0x02],
            min_geo_resolution: 5,
            export_allowed: false,
            key_id: [0xAB; 32],
            granted_at: 1_000_000,
            expires_at: None,
        }
    }

    fn sample_revoked() -> ConsentRevokedV1 {
        ConsentRevokedV1 {
            subject_id: EntityId::new(),
            key_id: [0xCD; 32],
            revoked_at: 2_000_000,
            reason: 0,
        }
    }

    // -- ConsentGrantedV1 --

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_v1_round_trip_no_expiry() {
        let g = sample_granted();
        let bytes = g.encode().unwrap();
        let d = ConsentGrantedV1::decode(&bytes).unwrap();
        assert_eq!(d.subject_id, g.subject_id);
        assert_eq!(d.grantee_id, g.grantee_id);
        assert_eq!(d.purpose, g.purpose);
        assert_eq!(d.modalities, g.modalities);
        assert_eq!(d.min_geo_resolution, g.min_geo_resolution);
        assert_eq!(d.export_allowed, g.export_allowed);
        assert_eq!(d.key_id, g.key_id);
        assert_eq!(d.granted_at, g.granted_at);
        assert_eq!(d.expires_at, None);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_v1_round_trip_with_expiry() {
        let mut g = sample_granted();
        g.expires_at = Some(9_999_999);
        let bytes = g.encode().unwrap();
        let d = ConsentGrantedV1::decode(&bytes).unwrap();
        assert_eq!(d.expires_at, Some(9_999_999));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_v1_export_allowed_true() {
        let mut g = sample_granted();
        g.export_allowed = true;
        let bytes = g.encode().unwrap();
        let d = ConsentGrantedV1::decode(&bytes).unwrap();
        assert!(d.export_allowed);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_v1_modalities_too_large_rejected() {
        let mut g = sample_granted();
        g.modalities = vec![0u8; MAX_MODALITIES_BYTES + 1];
        assert!(matches!(
            g.encode(),
            Err(ConsentCodecError::ModalitiesTooLarge { .. })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_v1_wrong_magic_rejected() {
        let g = sample_granted();
        let mut bytes = g.encode().unwrap().as_slice().to_vec();
        // byte[2] is 'C' in CGR1
        bytes[2] = b'X';
        assert!(matches!(
            ConsentGrantedV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(ConsentCodecError::WrongMagic)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_v1_trailing_bytes_rejected() {
        let g = sample_granted();
        let mut bytes = g.encode().unwrap().as_slice().to_vec();
        bytes.push(0x00);
        assert!(matches!(
            ConsentGrantedV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(ConsentCodecError::TrailingBytes)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_v1_wrong_version_rejected() {
        let g = sample_granted();
        let bytes = g.encode().unwrap().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).unwrap();
        if let Value::Array(ref mut items) = val {
            items[1] = Value::Integer(99_i64.into());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(matches!(
            ConsentGrantedV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongVersion)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_v1_wrong_array_length_rejected() {
        let truncated = Value::Array(vec![
            Value::Bytes(b"CGR1".to_vec()),
            Value::Integer(1.into()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&truncated, &mut buf).unwrap();
        assert!(matches!(
            ConsentGrantedV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongArrayLength)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_v1_wrong_field_type_for_subject_id() {
        let g = sample_granted();
        let bytes = g.encode().unwrap().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).unwrap();
        if let Value::Array(ref mut items) = val {
            items[2] = Value::Integer(42.into());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(matches!(
            ConsentGrantedV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongFieldType)
        ));
    }

    // -- ConsentRevokedV1 --

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_v1_round_trip() {
        let r = sample_revoked();
        let bytes = r.encode().unwrap();
        let d = ConsentRevokedV1::decode(&bytes).unwrap();
        assert_eq!(d.subject_id, r.subject_id);
        assert_eq!(d.key_id, r.key_id);
        assert_eq!(d.revoked_at, r.revoked_at);
        assert_eq!(d.reason, r.reason);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_v1_wrong_magic_rejected() {
        let r = sample_revoked();
        let mut bytes = r.encode().unwrap().as_slice().to_vec();
        bytes[2] = b'X';
        assert!(matches!(
            ConsentRevokedV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(ConsentCodecError::WrongMagic)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_v1_trailing_bytes_rejected() {
        let r = sample_revoked();
        let mut bytes = r.encode().unwrap().as_slice().to_vec();
        bytes.push(0xFF);
        assert!(matches!(
            ConsentRevokedV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(ConsentCodecError::TrailingBytes)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_v1_wrong_array_length_rejected() {
        let truncated = Value::Array(vec![Value::Bytes(b"CRV1".to_vec())]);
        let mut buf = Vec::new();
        ciborium::into_writer(&truncated, &mut buf).unwrap();
        assert!(matches!(
            ConsentRevokedV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongArrayLength)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_v1_wrong_field_type_for_key_id() {
        let r = sample_revoked();
        let bytes = r.encode().unwrap().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).unwrap();
        if let Value::Array(ref mut items) = val {
            items[3] = Value::Integer(42.into());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(matches!(
            ConsentRevokedV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongFieldType)
        ));
    }

    // -- ConsentGate --

    struct AllowAllGate;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl ConsentGate for AllowAllGate {
        fn check_consent(
            &self,
            _subject: EntityId,
            event_type: &Kind,
        ) -> Result<ConsentCapabilityToken, ConsentError> {
            if event_type.as_str().starts_with("consent.") {
                return Err(ConsentError::ConsentEventsForbidden);
            }
            Ok(ConsentCapabilityToken::new())
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_allows_non_consent_events() {
        let gate = AllowAllGate;
        let result = gate.check_consent(EntityId::new(), &Kind::new("world.observation.v1"));
        assert!(result.is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_forbids_consent_star_events() {
        let gate = AllowAllGate;
        let result = gate.check_consent(EntityId::new(), &Kind::new("consent.granted.v1"));
        assert_eq!(result.unwrap_err(), ConsentError::ConsentEventsForbidden);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_forbids_consent_revoked_events() {
        let gate = AllowAllGate;
        let result = gate.check_consent(EntityId::new(), &Kind::new("consent.revoked.v1"));
        assert_eq!(result.unwrap_err(), ConsentError::ConsentEventsForbidden);
    }

    // -- FieldState --

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn field_state_present() {
        let s = FieldState::Present(CanonicalBytes::from_vec(vec![0x01]));
        assert!(matches!(s, FieldState::Present(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn field_state_redacted_destroyed() {
        let s = FieldState::RedactedDestroyed;
        assert!(matches!(s, FieldState::RedactedDestroyed));
        assert_ne!(s, FieldState::Present(CanonicalBytes::from_vec(vec![])));
    }

    // -- Error display --

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_codec_error_display() {
        assert!(!ConsentCodecError::WrongMagic.to_string().is_empty());
        assert!(!ConsentCodecError::WrongVersion.to_string().is_empty());
        assert!(!ConsentCodecError::WrongArrayLength.to_string().is_empty());
        assert!(!ConsentCodecError::WrongFieldType.to_string().is_empty());
        assert!(!ConsentCodecError::TrailingBytes.to_string().is_empty());
        assert!(!ConsentCodecError::CborError.to_string().is_empty());
        assert!(!format!("{}", ConsentCodecError::ModalitiesTooLarge { size: 300 }).is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_error_display() {
        assert!(!ConsentError::NoConsent.to_string().is_empty());
        assert!(!ConsentError::Revoked.to_string().is_empty());
        assert!(!ConsentError::Expired.to_string().is_empty());
        assert!(!ConsentError::ConsentEventsForbidden.to_string().is_empty());
    }
}
