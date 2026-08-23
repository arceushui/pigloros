//! Consent, revocation, and key-lifecycle CBOR codecs (ADR-039).
//!
//! Owns event types `"consent.granted.v1"` and `"consent.revoked.v1"`.
//! These event types are **Gateway-only** per ADR-024 section 2 - no Plugin may
//! propose or observe consent events directly.

use std::io::Cursor;

use ciborium::Value;

use crate::{
    event::{CanonicalBytes, Kind},
    ids::EntityId,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Versioned event type for consent grants (ADR-039).
pub const EVENT_TYPE_CONSENT_GRANTED_V1: &str = "consent.granted.v1";

/// Versioned event type for consent revocations (ADR-039).
pub const EVENT_TYPE_CONSENT_REVOKED_V1: &str = "consent.revoked.v1";

/// Returns whether an event type is reserved to the Gateway consent host.
#[must_use]
pub fn is_consent_event_type(event_type: &Kind) -> bool {
    matches!(
        event_type.as_str(),
        EVENT_TYPE_CONSENT_GRANTED_V1 | EVENT_TYPE_CONSENT_REVOKED_V1
    )
}

// magic ASCII "CGV1" = h'43475631'
const MAGIC_CGV1: [u8; 4] = *b"CGV1";
// magic ASCII "CRV1" = h'43525631'
const MAGIC_CRV1: [u8; 4] = *b"CRV1";
const VERSION_V1: u8 = 1;

/// Maximum UTF-8 bytes for the `purpose` field in `ConsentGranted`.
pub const MAX_PURPOSE_BYTES: usize = 128;

/// Modality bitmask: location data.
pub const MODALITY_LOCATION: u8 = 0x01;
/// Modality bitmask: persona model.
pub const MODALITY_PERSONA: u8 = 0x02;
/// Modality bitmask: model fitting.
pub const MODALITY_MODEL_FIT: u8 = 0x04;
/// Modality bitmask: export permission.
pub const MODALITY_EXPORT: u8 = 0x08;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by consent CBOR codec operations.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConsentCodecError {
    #[error("wrong magic bytes")]
    WrongMagic,
    #[error("wrong schema version")]
    WrongVersion,
    #[error("wrong CBOR array length")]
    WrongArrayLength,
    #[error("wrong field type")]
    WrongFieldType,
    #[error("purpose string too long: {size} bytes (max {MAX_PURPOSE_BYTES})")]
    PurposeTooLong { size: usize },
    #[error("trailing bytes after CBOR item")]
    TrailingBytes,
    #[error("CBOR decode error")]
    CborError,
    #[error("non-canonical CBOR encoding")]
    NonCanonicalEncoding,
    #[error("field value is outside the V1 contract")]
    FieldOutOfBounds,
}

/// Errors returned by `ConsentGate::check_consent`.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConsentError {
    #[error("no active consent grant for this subject and event type")]
    NoConsent,
    #[error("consent has been revoked (fence_seq exceeded)")]
    Revoked,
    #[error("consent grant has expired")]
    Expired,
    /// `consent.*` event types are Gateway-only per ADR-024 section 2.
    #[error("consent.* event types are Gateway-only and cannot be accessed by plugins")]
    ConsentEventsForbidden,
}

// ---------------------------------------------------------------------------
// CBOR helpers (private)
// ---------------------------------------------------------------------------

fn cbor_bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn cbor_u8(v: u8) -> Value {
    Value::Integer(ciborium::value::Integer::from(v))
}

fn cbor_u16(v: u16) -> Value {
    Value::Integer(ciborium::value::Integer::from(v))
}

fn cbor_u32(v: u32) -> Value {
    Value::Integer(ciborium::value::Integer::from(v))
}

fn cbor_u64(v: u64) -> Value {
    Value::Integer(ciborium::value::Integer::from(v))
}

const fn cbor_bool(v: bool) -> Value {
    Value::Bool(v)
}

fn cbor_tstr(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn cbor_id(id: EntityId) -> Value {
    let n: u128 = id.inner().into();
    cbor_bytes(&n.to_be_bytes())
}

fn cbor_encode(value: &Value) -> Result<Vec<u8>, ConsentCodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| ConsentCodecError::CborError)?;
    Ok(buf)
}

fn decode_array(bytes: &[u8], expected_len: usize) -> Result<Vec<Value>, ConsentCodecError> {
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::from_reader(&mut cursor).map_err(|_| ConsentCodecError::CborError)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ConsentCodecError::TrailingBytes);
    }
    if cbor_encode(&value)? != bytes {
        return Err(ConsentCodecError::NonCanonicalEncoding);
    }
    match value {
        Value::Array(items) if items.len() == expected_len => Ok(items),
        Value::Array(_) => Err(ConsentCodecError::WrongArrayLength),
        _ => Err(ConsentCodecError::CborError),
    }
}

fn decode_magic(val: &Value, expected: [u8; 4]) -> Result<(), ConsentCodecError> {
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

fn decode_u16(val: &Value) -> Result<u16, ConsentCodecError> {
    match val {
        Value::Integer(n) => u16::try_from(*n).map_err(|_| ConsentCodecError::WrongFieldType),
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

fn decode_u32(val: &Value) -> Result<u32, ConsentCodecError> {
    match val {
        Value::Integer(n) => u32::try_from(*n).map_err(|_| ConsentCodecError::WrongFieldType),
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

fn decode_u64(val: &Value) -> Result<u64, ConsentCodecError> {
    match val {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| ConsentCodecError::WrongFieldType),
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

const fn decode_bool(val: &Value) -> Result<bool, ConsentCodecError> {
    match val {
        Value::Bool(b) => Ok(*b),
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

fn decode_id(val: &Value) -> Result<EntityId, ConsentCodecError> {
    match val {
        Value::Bytes(b) if b.len() == 16 => {
            let Ok(arr) = b.as_slice().try_into() else {
                return Err(ConsentCodecError::WrongFieldType);
            };
            let n = u128::from_be_bytes(arr);
            Ok(EntityId::from_ulid(ulid::Ulid::from(n)))
        }
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

fn decode_tstr_max(val: &Value, max: usize) -> Result<String, ConsentCodecError> {
    match val {
        Value::Text(s) => {
            if s.len() > max {
                Err(ConsentCodecError::PurposeTooLong { size: s.len() })
            } else {
                Ok(s.clone())
            }
        }
        _ => Err(ConsentCodecError::WrongFieldType),
    }
}

// ---------------------------------------------------------------------------
// ConsentGranted
// ---------------------------------------------------------------------------

/// A consent grant event (ADR-039, `consent.granted.v1`).
///
/// Array (12 elements):
/// `[magic_bstr4="CGV1", version_u8=1, subject_id_bstr16, grantee_id_bstr16,
///   purpose_tstr, modalities_u8, min_geo_resolution_u8,
///   fork_permitted_bool, export_permitted_bool,
///   retention_days_u16, expiry_secs_u32, grant_seq_u64]`
///
/// `expiry_secs`: 0 = no expiry. `retention_days`: 0 = session-only.
/// `grant_seq`: Timeline.seq at the time this event was appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGranted {
    pub subject_id: EntityId,
    pub grantee_id: EntityId,
    /// UTF-8 string, max 128 bytes.
    pub purpose: String,
    /// Bitmask of the documented modality constants.
    pub modalities: u8,
    /// 0 = no floor, 1 = 0.1-degree (ADR-026 floor).
    pub min_geo_resolution: u8,
    pub fork_permitted: bool,
    pub export_permitted: bool,
    /// 0 = session-only.
    pub retention_days: u16,
    /// 0 = no expiry.
    pub expiry_secs: u32,
    /// Timeline.seq at grant time.
    pub grant_seq: u64,
}

impl ConsentGranted {
    /// Encode to canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns [`ConsentCodecError::PurposeTooLong`] if `purpose` exceeds 128 bytes.
    pub fn encode(&self) -> Result<CanonicalBytes, ConsentCodecError> {
        if self.purpose.len() > MAX_PURPOSE_BYTES {
            return Err(ConsentCodecError::PurposeTooLong {
                size: self.purpose.len(),
            });
        }
        let arr = Value::Array(vec![
            cbor_bytes(&MAGIC_CGV1),
            cbor_u8(VERSION_V1),
            cbor_id(self.subject_id),
            cbor_id(self.grantee_id),
            cbor_tstr(&self.purpose),
            cbor_u8(self.modalities),
            cbor_u8(self.min_geo_resolution),
            cbor_bool(self.fork_permitted),
            cbor_bool(self.export_permitted),
            cbor_u16(self.retention_days),
            cbor_u32(self.expiry_secs),
            cbor_u64(self.grant_seq),
        ]);
        Ok(CanonicalBytes::from_vec(cbor_encode(&arr)?))
    }

    /// Decode from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns a [`ConsentCodecError`] on any malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, ConsentCodecError> {
        let items = decode_array(bytes.as_slice(), 12)?;
        decode_magic(&items[0], MAGIC_CGV1)?;
        decode_version(&items[1])?;
        let subject_id = decode_id(&items[2])?;
        let grantee_id = decode_id(&items[3])?;
        let purpose = decode_tstr_max(&items[4], MAX_PURPOSE_BYTES)?;
        let modalities = decode_u8(&items[5])?;
        let min_geo_resolution = decode_u8(&items[6])?;
        if modalities & !0x0F != 0 || min_geo_resolution > 1 {
            return Err(ConsentCodecError::FieldOutOfBounds);
        }
        let fork_permitted = decode_bool(&items[7])?;
        let export_permitted = decode_bool(&items[8])?;
        let retention_days = decode_u16(&items[9])?;
        let expiry_secs = decode_u32(&items[10])?;
        let grant_seq = decode_u64(&items[11])?;
        Ok(Self {
            subject_id,
            grantee_id,
            purpose,
            modalities,
            min_geo_resolution,
            fork_permitted,
            export_permitted,
            retention_days,
            expiry_secs,
            grant_seq,
        })
    }
}

// ---------------------------------------------------------------------------
// ConsentRevoked
// ---------------------------------------------------------------------------

/// A consent revocation event (ADR-039, `consent.revoked.v1`).
///
/// Array (6 elements):
/// `[magic_bstr4="CRV1", version_u8=1, subject_id_bstr16, grantee_id_bstr16,
///   grant_seq_u64, fence_seq_u64]`
///
/// `fence_seq`: Timeline.seq at revocation. Sessions with
/// `logical_head >= fence_seq` must terminate immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRevoked {
    pub subject_id: EntityId,
    pub grantee_id: EntityId,
    /// Timeline.seq of the `consent.granted.v1` being revoked.
    pub grant_seq: u64,
    /// Timeline.seq at revocation. Sessions past this seq must close.
    pub fence_seq: u64,
}

/// Current V1 name for the consent grant contract.
pub type ConsentGrantedV1 = ConsentGranted;
/// Current V1 name for the consent revocation contract.
pub type ConsentRevokedV1 = ConsentRevoked;

impl ConsentRevoked {
    /// Encode to canonical CBOR bytes.
    ///
    /// # Errors
    /// This function is currently infallible but returns `Result` for API consistency.
    pub fn encode(&self) -> Result<CanonicalBytes, ConsentCodecError> {
        let arr = Value::Array(vec![
            cbor_bytes(&MAGIC_CRV1),
            cbor_u8(VERSION_V1),
            cbor_id(self.subject_id),
            cbor_id(self.grantee_id),
            cbor_u64(self.grant_seq),
            cbor_u64(self.fence_seq),
        ]);
        Ok(CanonicalBytes::from_vec(cbor_encode(&arr)?))
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
        let grantee_id = decode_id(&items[3])?;
        let grant_seq = decode_u64(&items[4])?;
        let fence_seq = decode_u64(&items[5])?;
        Ok(Self {
            subject_id,
            grantee_id,
            grant_seq,
            fence_seq,
        })
    }
}

// ---------------------------------------------------------------------------
// ConsentCapabilityToken and ConsentGate
// ---------------------------------------------------------------------------

/// Capability token issued by the Gateway on a valid `consent.granted.v1`.
///
/// Callers must present this token before emitting event drafts or reading
/// sensitive Projection fields for a human-subject entity. Per-step check:
/// `token.fence_seq > current_timeline_head` (ADR-039 section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentCapabilityToken {
    pub subject_id: EntityId,
    pub grantee_id: EntityId,
    pub modalities: u8,
    pub grant_seq: u64,
    /// `u64::MAX` until revocation; set to `consent.revoked.v1.fence_seq` on revocation.
    pub fence_seq: u64,
}

impl ConsentCapabilityToken {
    /// Construct a new token from a consent grant.
    ///
    /// `fence_seq` starts at `u64::MAX` and is updated to the revocation
    /// `fence_seq` when a matching `consent.revoked.v1` is folded.
    #[must_use]
    pub const fn from_grant(grant: &ConsentGranted) -> Self {
        Self {
            subject_id: grant.subject_id,
            grantee_id: grant.grantee_id,
            modalities: grant.modalities,
            grant_seq: grant.grant_seq,
            fence_seq: u64::MAX,
        }
    }

    /// Return `true` if this token is still valid at `timeline_head`.
    ///
    /// Valid when `fence_seq > timeline_head`.
    #[must_use]
    pub const fn is_valid_at(&self, timeline_head: u64) -> bool {
        self.fence_seq > timeline_head
    }

    /// Apply the matching durable revocation without mutating Timeline history.
    ///
    /// A repeated or earlier fence can only preserve or further restrict access.
    ///
    /// # Errors
    /// Returns the closed no-consent error when the revocation names another grant.
    pub fn invalidate_with(&mut self, revocation: &ConsentRevoked) -> Result<(), ConsentError> {
        if self.subject_id != revocation.subject_id
            || self.grantee_id != revocation.grantee_id
            || self.grant_seq != revocation.grant_seq
        {
            return Err(ConsentError::NoConsent);
        }
        self.fence_seq = self.fence_seq.min(revocation.fence_seq);
        Ok(())
    }
}

/// Plugin seam for consent enforcement (ADR-039).
///
/// Equivalent to `GeoLocationAdmissionStore` - prevents plugins from
/// accessing sensitive event types without a valid, non-revoked consent grant.
pub trait ConsentGate: Send + Sync {
    /// Check whether `subject` holds an active, non-revoked consent grant
    /// that covers `event_type` at `timeline_head`.
    ///
    /// Returns [`ConsentError::ConsentEventsForbidden`] for `consent.*` event
    /// types (Gateway-only per ADR-024 section 2).
    ///
    /// Returns [`ConsentError::Revoked`] if `token.fence_seq <= timeline_head`.
    ///
    /// # Errors
    /// Returns a [`ConsentError`] describing why consent was not granted.
    fn check_consent(
        &self,
        subject: EntityId,
        event_type: &Kind,
        timeline_head: u64,
    ) -> Result<ConsentCapabilityToken, ConsentError>;
}

// ---------------------------------------------------------------------------
// ConsentRevocationFoldListener
// ---------------------------------------------------------------------------

/// Listener implemented by `ProjectionRegistry` to invalidate caches on
/// revocation (ADR-039 section 5).
///
/// On folding a `consent.revoked.v1` event the registry must immediately
/// flush all projection cache entries scoped to `subject_id`.
pub trait ConsentRevocationFoldListener: Send + Sync {
    fn on_consent_revoked(&mut self, subject_id: EntityId, fence_seq: u64);
}

// ---------------------------------------------------------------------------
// FieldState - Replay sentinel for destroyed keys (ADR-039)
// ---------------------------------------------------------------------------

/// State of a sensitive field when replaying after key destruction.
///
/// When a subject's data key is destroyed on revocation, Replay returns
/// `FieldState::RedactedDestroyed` for encrypted fields - not an error,
/// not null - so Replay remains deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldState {
    /// The field is present and decryptable.
    Present(CanonicalBytes),
    /// The field's encryption key has been destroyed; content is unavailable.
    RedactedDestroyed,
}

impl FieldState {
    /// Compose a later erasure/redaction outcome without ever restoring data.
    #[must_use]
    pub fn redacted_destroyed(self) -> Self {
        match self {
            Self::Present(_) | Self::RedactedDestroyed => Self::RedactedDestroyed,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{event::Kind, ids::EntityId};

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected consent fixture error: {error:?}"
                )))
            })
        }
    }

    trait TestErrorExt<E> {
        fn test_err(self) -> E;
    }

    impl<T, E: std::fmt::Debug> TestErrorExt<E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(_) => std::panic::resume_unwind(Box::new("expected consent fixture error")),
                Err(error) => error,
            }
        }
    }

    fn sample_granted() -> ConsentGranted {
        ConsentGranted {
            subject_id: EntityId::new(),
            grantee_id: EntityId::new(),
            purpose: "decision-preview".to_owned(),
            modalities: MODALITY_LOCATION | MODALITY_PERSONA,
            min_geo_resolution: 1,
            fork_permitted: true,
            export_permitted: false,
            retention_days: 30,
            expiry_secs: 0,
            grant_seq: 42,
        }
    }

    fn sample_revoked(grant: &ConsentGranted) -> ConsentRevoked {
        ConsentRevoked {
            subject_id: grant.subject_id,
            grantee_id: grant.grantee_id,
            grant_seq: grant.grant_seq,
            fence_seq: 100,
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn only_exact_gateway_consent_event_types_are_reserved() {
        assert!(is_consent_event_type(&Kind::new(
            EVENT_TYPE_CONSENT_GRANTED_V1
        )));
        assert!(is_consent_event_type(&Kind::new(
            EVENT_TYPE_CONSENT_REVOKED_V1
        )));
        assert!(!is_consent_event_type(&Kind::new("consent.granted.v2")));
        assert!(!is_consent_event_type(&Kind::new("world.observation.v1")));
    }

    // -- ConsentGranted --

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_round_trip() {
        let g = sample_granted();
        let bytes = g.encode().test_ok();
        let d = ConsentGranted::decode(&bytes).test_ok();
        assert_eq!(d.subject_id, g.subject_id);
        assert_eq!(d.grantee_id, g.grantee_id);
        assert_eq!(d.purpose, g.purpose);
        assert_eq!(d.modalities, g.modalities);
        assert_eq!(d.min_geo_resolution, g.min_geo_resolution);
        assert_eq!(d.fork_permitted, g.fork_permitted);
        assert_eq!(d.export_permitted, g.export_permitted);
        assert_eq!(d.retention_days, g.retention_days);
        assert_eq!(d.expiry_secs, g.expiry_secs);
        assert_eq!(d.grant_seq, g.grant_seq);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_all_modalities() {
        let mut g = sample_granted();
        g.modalities = MODALITY_LOCATION | MODALITY_PERSONA | MODALITY_MODEL_FIT | MODALITY_EXPORT;
        g.export_permitted = true;
        let bytes = g.encode().test_ok();
        let d = ConsentGranted::decode(&bytes).test_ok();
        assert_eq!(d.modalities, 0x0F);
        assert!(d.export_permitted);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_non_zero_expiry() {
        let mut g = sample_granted();
        g.expiry_secs = 86_400;
        let bytes = g.encode().test_ok();
        let d = ConsentGranted::decode(&bytes).test_ok();
        assert_eq!(d.expiry_secs, 86_400);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_purpose_too_long_rejected() {
        let mut g = sample_granted();
        g.purpose = "x".repeat(MAX_PURPOSE_BYTES + 1);
        assert!(matches!(
            g.encode(),
            Err(ConsentCodecError::PurposeTooLong { .. })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_wrong_magic_rejected() {
        let g = sample_granted();
        let mut bytes = g.encode().test_ok().as_slice().to_vec();
        // byte[2] is the first payload byte of the magic bstr
        bytes[2] = b'X';
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(bytes)),
            Err(ConsentCodecError::WrongMagic)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_trailing_bytes_rejected() {
        let g = sample_granted();
        let mut bytes = g.encode().test_ok().as_slice().to_vec();
        bytes.push(0x00);
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(bytes)),
            Err(ConsentCodecError::TrailingBytes)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_non_canonical_array_encoding_is_rejected() {
        let grant = sample_granted();
        let canonical = grant.encode().test_ok();
        let mut non_canonical = vec![0x98, 12];
        non_canonical.extend_from_slice(&canonical.as_slice()[1..]);
        assert_eq!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(non_canonical)).test_err(),
            ConsentCodecError::NonCanonicalEncoding
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_wrong_version_rejected() {
        let g = sample_granted();
        let bytes = g.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).test_ok();
        if let Value::Array(ref mut items) = val {
            items[1] = Value::Integer(99_i64.into());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongVersion)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_wrong_array_length_rejected() {
        let truncated = Value::Array(vec![
            Value::Bytes(b"CGV1".to_vec()),
            Value::Integer(1.into()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&truncated, &mut buf).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongArrayLength)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_root_non_array_rejected() {
        let scalar = Value::Integer(42.into());
        let mut buf = Vec::new();
        ciborium::into_writer(&scalar, &mut buf).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::CborError)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_wrong_field_type_for_subject_id() {
        let g = sample_granted();
        let bytes = g.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).test_ok();
        if let Value::Array(ref mut items) = val {
            items[2] = Value::Integer(42.into());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_wrong_length_bytes_for_subject_id() {
        // decode_id rejects bstr that is not exactly 16 bytes
        let g = sample_granted();
        let bytes = g.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).test_ok();
        if let Value::Array(ref mut items) = val {
            items[2] = Value::Bytes(vec![0u8; 15]); // wrong length (15 not 16)
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_wrong_field_type_for_fork_permitted() {
        let g = sample_granted();
        let bytes = g.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).test_ok();
        if let Value::Array(ref mut items) = val {
            items[7] = Value::Integer(1.into()); // integer not bool
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_wrong_field_type_for_retention_days() {
        let g = sample_granted();
        let bytes = g.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).test_ok();
        if let Value::Array(ref mut items) = val {
            items[9] = Value::Text("not_u16".to_owned());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_wrong_field_type_for_expiry_secs() {
        let g = sample_granted();
        let bytes = g.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).test_ok();
        if let Value::Array(ref mut items) = val {
            items[10] = Value::Text("not_u32".to_owned());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_wrong_field_type_for_modalities() {
        let g = sample_granted();
        let bytes = g.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).test_ok();
        if let Value::Array(ref mut items) = val {
            // modalities is at index 5; put a text value there
            items[5] = Value::Text("not_a_u8".to_owned());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_purpose_wrong_type_rejected() {
        let g = sample_granted();
        let bytes = g.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).test_ok();
        if let Value::Array(ref mut items) = val {
            items[4] = Value::Integer(99.into()); // purpose should be tstr
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_decoding_rejects_overlong_purpose_and_unknown_bounds() {
        let grant = sample_granted();
        let bytes = grant.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut value: Value = ciborium::from_reader(&mut cursor).test_ok();
        if let Value::Array(items) = &mut value {
            items[4] = Value::Text("x".repeat(MAX_PURPOSE_BYTES + 1));
        }
        let mut overlong = Vec::new();
        ciborium::into_writer(&value, &mut overlong).test_ok();
        assert!(matches!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(overlong)),
            Err(ConsentCodecError::PurposeTooLong { .. })
        ));

        let mut value: Value = ciborium::from_reader(&mut std::io::Cursor::new(bytes)).test_ok();
        if let Value::Array(items) = &mut value {
            items[5] = Value::Integer(0x10_u8.into());
        }
        let mut out_of_bounds = Vec::new();
        ciborium::into_writer(&value, &mut out_of_bounds).test_ok();
        assert_eq!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(out_of_bounds)).test_err(),
            ConsentCodecError::FieldOutOfBounds
        );
    }

    // -- ConsentRevoked --

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_round_trip() {
        let g = sample_granted();
        let r = sample_revoked(&g);
        let bytes = r.encode().test_ok();
        let d = ConsentRevoked::decode(&bytes).test_ok();
        assert_eq!(d.subject_id, r.subject_id);
        assert_eq!(d.grantee_id, r.grantee_id);
        assert_eq!(d.grant_seq, r.grant_seq);
        assert_eq!(d.fence_seq, r.fence_seq);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_wrong_magic_rejected() {
        let g = sample_granted();
        let r = sample_revoked(&g);
        let mut bytes = r.encode().test_ok().as_slice().to_vec();
        bytes[2] = b'X';
        assert!(matches!(
            ConsentRevoked::decode(&CanonicalBytes::from_vec(bytes)),
            Err(ConsentCodecError::WrongMagic)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_trailing_bytes_rejected() {
        let g = sample_granted();
        let r = sample_revoked(&g);
        let mut bytes = r.encode().test_ok().as_slice().to_vec();
        bytes.push(0xFF);
        assert!(matches!(
            ConsentRevoked::decode(&CanonicalBytes::from_vec(bytes)),
            Err(ConsentCodecError::TrailingBytes)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_wrong_array_length_rejected() {
        let truncated = Value::Array(vec![Value::Bytes(b"CRV1".to_vec())]);
        let mut buf = Vec::new();
        ciborium::into_writer(&truncated, &mut buf).test_ok();
        assert!(matches!(
            ConsentRevoked::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongArrayLength)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_root_non_array_rejected() {
        let scalar = Value::Bool(false);
        let mut buf = Vec::new();
        ciborium::into_writer(&scalar, &mut buf).test_ok();
        assert!(matches!(
            ConsentRevoked::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::CborError)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revoked_wrong_field_type_for_fence_seq() {
        let g = sample_granted();
        let r = sample_revoked(&g);
        let bytes = r.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: Value = ciborium::from_reader(&mut cursor).test_ok();
        if let Value::Array(ref mut items) = val {
            items[5] = Value::Text("not_a_u64".to_owned());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            ConsentRevoked::decode(&CanonicalBytes::from_vec(buf)),
            Err(ConsentCodecError::WrongFieldType)
        ));
    }

    // -- ConsentCapabilityToken --

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn token_from_grant_starts_with_max_fence_seq() {
        let g = sample_granted();
        let token = ConsentCapabilityToken::from_grant(&g);
        assert_eq!(token.fence_seq, u64::MAX);
        assert_eq!(token.grant_seq, g.grant_seq);
        assert_eq!(token.modalities, g.modalities);
        assert_eq!(token.subject_id, g.subject_id);
        assert_eq!(token.grantee_id, g.grantee_id);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn token_is_valid_before_fence_seq() {
        let g = sample_granted();
        let token = ConsentCapabilityToken::from_grant(&g);
        assert!(token.is_valid_at(0));
        assert!(token.is_valid_at(u64::MAX - 1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn token_is_invalid_at_or_after_fence_seq() {
        let g = sample_granted();
        let mut token = ConsentCapabilityToken::from_grant(&g);
        token.fence_seq = 100;
        assert!(!token.is_valid_at(100));
        assert!(!token.is_valid_at(200));
        assert!(token.is_valid_at(99));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn matching_revocation_only_tightens_a_token_fence() {
        let grant = sample_granted();
        let mut token = ConsentCapabilityToken::from_grant(&grant);
        let revocation = sample_revoked(&grant);
        assert!(token.invalidate_with(&revocation).is_ok());
        assert!(!token.is_valid_at(revocation.fence_seq));
        let later = ConsentRevoked {
            fence_seq: revocation.fence_seq + 1,
            ..revocation
        };
        assert!(token.invalidate_with(&later).is_ok());
        assert!(!token.is_valid_at(100));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nonmatching_revocation_is_not_applied() {
        let grant = sample_granted();
        let mut token = ConsentCapabilityToken::from_grant(&grant);
        let mut revocation = sample_revoked(&grant);
        revocation.grant_seq += 1;
        assert_eq!(
            token.invalidate_with(&revocation),
            Err(ConsentError::NoConsent)
        );
        assert!(token.is_valid_at(u64::MAX - 1));
    }

    // -- ConsentGate --

    struct TestGate {
        token: ConsentCapabilityToken,
    }

    impl ConsentGate for TestGate {
        fn check_consent(
            &self,
            _subject: EntityId,
            event_type: &Kind,
            timeline_head: u64,
        ) -> Result<ConsentCapabilityToken, ConsentError> {
            if event_type.as_str().starts_with("consent.") {
                return Err(ConsentError::ConsentEventsForbidden);
            }
            if !self.token.is_valid_at(timeline_head) {
                return Err(ConsentError::Revoked);
            }
            Ok(self.token.clone())
        }
    }

    fn test_gate(fence_seq: u64) -> TestGate {
        let g = sample_granted();
        let mut token = ConsentCapabilityToken::from_grant(&g);
        token.fence_seq = fence_seq;
        TestGate { token }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_allows_non_consent_event_within_fence() {
        let gate = test_gate(u64::MAX);
        assert!(gate
            .check_consent(EntityId::new(), &Kind::new("world.observation.v1"), 50)
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_forbids_consent_granted_events() {
        let gate = test_gate(u64::MAX);
        assert_eq!(
            gate.check_consent(
                EntityId::new(),
                &Kind::new(EVENT_TYPE_CONSENT_GRANTED_V1),
                0
            )
            .test_err(),
            ConsentError::ConsentEventsForbidden
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_forbids_consent_revoked_events() {
        let gate = test_gate(u64::MAX);
        assert_eq!(
            gate.check_consent(
                EntityId::new(),
                &Kind::new(EVENT_TYPE_CONSENT_REVOKED_V1),
                0
            )
            .test_err(),
            ConsentError::ConsentEventsForbidden
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_rejects_when_fence_exceeded() {
        let gate = test_gate(100);
        assert_eq!(
            gate.check_consent(
                EntityId::new(),
                &Kind::new("world.observation.v1"),
                100 // head == fence -> invalid
            )
            .test_err(),
            ConsentError::Revoked
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_allows_just_before_fence() {
        let gate = test_gate(100);
        assert!(gate
            .check_consent(EntityId::new(), &Kind::new("persona.update.v1"), 99)
            .is_ok());
    }

    // -- FieldState --

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn field_state_present_and_redacted() {
        let present = FieldState::Present(CanonicalBytes::from_vec(vec![0x01]));
        assert!(matches!(present, FieldState::Present(_)));
        let redacted = FieldState::RedactedDestroyed;
        assert!(matches!(redacted, FieldState::RedactedDestroyed));
        assert_ne!(
            redacted,
            FieldState::Present(CanonicalBytes::from_vec(vec![]))
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn field_state_redaction_is_irreversible() {
        let erased = FieldState::Present(CanonicalBytes::from_vec(vec![0x01])).redacted_destroyed();
        assert_eq!(erased, FieldState::RedactedDestroyed);
        assert_eq!(erased.redacted_destroyed(), FieldState::RedactedDestroyed);
    }

    // -- Error display --

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn codec_error_display() {
        assert!(!ConsentCodecError::WrongMagic.to_string().is_empty());
        assert!(!ConsentCodecError::WrongVersion.to_string().is_empty());
        assert!(!ConsentCodecError::WrongArrayLength.to_string().is_empty());
        assert!(!ConsentCodecError::WrongFieldType.to_string().is_empty());
        assert!(!ConsentCodecError::TrailingBytes.to_string().is_empty());
        assert!(!ConsentCodecError::CborError.to_string().is_empty());
        assert!(!format!("{}", ConsentCodecError::PurposeTooLong { size: 200 }).is_empty());
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
