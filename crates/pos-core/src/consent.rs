//! Consent, revocation, and key-lifecycle CBOR codecs (ADR-039).
//!
//! Owns event types `"consent.granted.v1"` and `"consent.revoked.v1"`.
//! These event types are **Gateway-only** per ADR-024 section 2 - no Plugin may
//! propose or observe consent events directly.

use std::{
    collections::HashMap,
    io::Cursor,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use ciborium::Value;

use crate::{
    event::{CanonicalBytes, Kind},
    ids::{EntityId, TimelineId},
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Versioned event type for consent grants (ADR-039).
pub const EVENT_TYPE_CONSENT_GRANTED_V1: &str = "consent.granted.v1";

/// Versioned event type for consent revocations (ADR-039).
pub const EVENT_TYPE_CONSENT_REVOKED_V1: &str = "consent.revoked.v1";

/// Host-owned lifecycle marker used when a non-Gateway host closes consent.
pub const HOST_CONSENT_CLOSED_EVENT_TYPE: &str = "experiment.lifecycle.consent-closed.v1";

/// Returns whether an event type is reserved to the Gateway consent host.
#[must_use]
pub fn is_consent_event_type(event_type: &Kind) -> bool {
    event_type.as_str().starts_with("consent.")
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

/// Maximum durable consent events accepted by one authority recovery pass.
pub const MAX_CONSENT_HISTORY_EVENTS: usize = 10_000;

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
    #[error("consent revocation has no matching durable grant")]
    UnmatchedRevocation,
    #[error("consent history has too many events: {count} (max {MAX_CONSENT_HISTORY_EVENTS})")]
    HistoryTooLong { count: usize },
    #[error("consent event coordinates do not match the durable payload")]
    HistoryCoordinateMismatch,
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
    #[error("consent grant does not cover the requested event modality")]
    ModalityNotGranted,
    #[error("consent grant does not permit export")]
    ExportNotPermitted,
    #[error("consent grant does not permit Timeline forks")]
    ForkNotPermitted,
    #[error("consent grant does not permit the requested geographic resolution")]
    GeoResolutionNotPermitted,
    #[error("consent grant does not permit the requested retention period")]
    RetentionNotPermitted,
    /// `consent.*` event types are Gateway-only per ADR-024 section 2.
    #[error("consent.* event types are Gateway-only and cannot be accessed by plugins")]
    ConsentEventsForbidden,
}

#[must_use]
pub fn required_modality_for_event(event_type: &Kind) -> u8 {
    let event_type = event_type.as_str();
    if event_type.starts_with("geo.") || event_type.starts_with("location.") {
        MODALITY_LOCATION
    } else if event_type.starts_with("persona.") {
        MODALITY_PERSONA
    } else if event_type.starts_with("model.") {
        MODALITY_MODEL_FIT
    } else if event_type.starts_with("export.") {
        MODALITY_EXPORT
    } else {
        0
    }
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
    ciborium::into_writer(value, &mut buf)
        .map_err(|_| ConsentCodecError::CborError)
        .map(|()| buf)
}

fn decode_array(bytes: &[u8], expected_len: usize) -> Result<Vec<Value>, ConsentCodecError> {
    let mut cursor = Cursor::new(bytes);
    ciborium::from_reader(&mut cursor)
        .map_err(|_| ConsentCodecError::CborError)
        .and_then(|value| {
            if cursor.position() != bytes.len() as u64 {
                return Err(ConsentCodecError::TrailingBytes);
            }
            cbor_encode(&value).and_then(|canonical| {
                if canonical != bytes {
                    return Err(ConsentCodecError::NonCanonicalEncoding);
                }
                match value {
                    Value::Array(items) if items.len() == expected_len => Ok(items),
                    Value::Array(_) => Err(ConsentCodecError::WrongArrayLength),
                    _ => Err(ConsentCodecError::CborError),
                }
            })
        })
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
            let mut arr = [0_u8; 16];
            arr.copy_from_slice(b);
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
    /// Validate every value-level constraint of the V1 grant contract.
    ///
    /// This single validation boundary is used both before encoding and after
    /// decoding so the encoder cannot emit a grant its decoder rejects.
    ///
    /// # Errors
    /// Returns a closed codec error when a field is outside the V1 contract.
    pub const fn validate(&self) -> Result<(), ConsentCodecError> {
        if self.purpose.len() > MAX_PURPOSE_BYTES {
            return Err(ConsentCodecError::PurposeTooLong {
                size: self.purpose.len(),
            });
        }
        if self.modalities & !0x0F != 0 || self.min_geo_resolution > 1 {
            return Err(ConsentCodecError::FieldOutOfBounds);
        }
        Ok(())
    }

    /// Encode to canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns [`ConsentCodecError::PurposeTooLong`] if `purpose` exceeds 128 bytes.
    pub fn encode(&self) -> Result<CanonicalBytes, ConsentCodecError> {
        self.validate().and_then(|()| {
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
            cbor_encode(&arr).map(CanonicalBytes::from_vec)
        })
    }

    /// Decode from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns a [`ConsentCodecError`] on any malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, ConsentCodecError> {
        decode_array(bytes.as_slice(), 12).and_then(|items| {
            decode_magic(&items[0], MAGIC_CGV1)
                .and_then(|()| decode_version(&items[1]))
                .and_then(|()| decode_id(&items[2]))
                .and_then(|subject_id| {
                    decode_id(&items[3]).and_then(|grantee_id| {
                        decode_tstr_max(&items[4], MAX_PURPOSE_BYTES).and_then(|purpose| {
                            decode_u8(&items[5]).and_then(|modalities| {
                                decode_u8(&items[6]).and_then(|min_geo_resolution| {
                                    decode_bool(&items[7]).and_then(|fork_permitted| {
                                        decode_bool(&items[8]).and_then(|export_permitted| {
                                            decode_u16(&items[9]).and_then(|retention_days| {
                                                decode_u32(&items[10]).and_then(|expiry_secs| {
                                                    decode_u64(&items[11])
                                                        .map(|grant_seq| Self {
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
                                                        .and_then(|grant| {
                                                            grant.validate().map(|()| grant)
                                                        })
                                                })
                                            })
                                        })
                                    })
                                })
                            })
                        })
                    })
                })
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
        cbor_encode(&arr).map(CanonicalBytes::from_vec)
    }

    /// Decode from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns a [`ConsentCodecError`] on any malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, ConsentCodecError> {
        decode_array(bytes.as_slice(), 6).and_then(|items| {
            decode_magic(&items[0], MAGIC_CRV1)
                .and_then(|()| decode_version(&items[1]))
                .and_then(|()| decode_id(&items[2]))
                .and_then(|subject_id| {
                    decode_id(&items[3]).and_then(|grantee_id| {
                        decode_u64(&items[4]).and_then(|grant_seq| {
                            decode_u64(&items[5]).map(|fence_seq| Self {
                                subject_id,
                                grantee_id,
                                grant_seq,
                                fence_seq,
                            })
                        })
                    })
                })
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
/// `token.fence_seq > current_timeline_head` and the durable grant policy is
/// rechecked at the operation's current time (ADR-039 section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentCapabilityToken {
    authority_id: u64,
    timeline_id: TimelineId,
    subject_id: EntityId,
    grantee_id: EntityId,
    modalities: u8,
    min_geo_resolution: u8,
    fork_permitted: bool,
    export_permitted: bool,
    retention_days: u16,
    grant_seq: u64,
    /// `u64::MAX` until revocation; set to `consent.revoked.v1.fence_seq` on revocation.
    fence_seq: u64,
}

impl ConsentCapabilityToken {
    /// Return `true` if this token is still valid at `timeline_head`.
    ///
    /// Valid when `fence_seq > timeline_head`.
    #[must_use]
    pub const fn is_valid_at(&self, timeline_head: u64) -> bool {
        self.fence_seq > timeline_head
    }

    /// Return the subject bound to this host-issued capability.
    #[must_use]
    pub const fn subject_id(&self) -> EntityId {
        self.subject_id
    }

    /// Return the grantee bound to this host-issued capability.
    #[must_use]
    pub const fn grantee_id(&self) -> EntityId {
        self.grantee_id
    }

    /// Return the durable sequence of the bound grant.
    #[must_use]
    pub const fn grant_seq(&self) -> u64 {
        self.grant_seq
    }

    /// Return the Timeline bound to this host-issued capability.
    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    /// Return the minimum geographic resolution permitted by the grant.
    #[must_use]
    pub const fn min_geo_resolution(&self) -> u8 {
        self.min_geo_resolution
    }

    /// Return whether the grant permits Timeline forks.
    #[must_use]
    pub const fn fork_permitted(&self) -> bool {
        self.fork_permitted
    }

    /// Return whether the grant permits export operations.
    #[must_use]
    pub const fn export_permitted(&self) -> bool {
        self.export_permitted
    }

    /// Return the durable retention period in days.
    #[must_use]
    pub const fn retention_days(&self) -> u16 {
        self.retention_days
    }

    /// Enforce the durable policy attached to one event family.
    ///
    /// Unknown event families are public by default; sensitive families must
    /// match both the modality bit and any policy flag they imply.
    ///
    /// # Errors
    /// Returns the specific policy error when this token cannot authorize the
    /// requested event family.
    pub fn authorize_event_type(&self, event_type: &Kind) -> Result<(), ConsentError> {
        let required_modality = required_modality_for_event(event_type);
        if required_modality != 0 && self.modalities & required_modality != required_modality {
            return Err(ConsentError::ModalityNotGranted);
        }
        if required_modality == MODALITY_EXPORT && !self.export_permitted {
            return Err(ConsentError::ExportNotPermitted);
        }
        if event_type.as_str().starts_with("timeline.fork.") && !self.fork_permitted {
            return Err(ConsentError::ForkNotPermitted);
        }
        if event_type.as_str().starts_with("retention.") && self.retention_days == 0 {
            return Err(ConsentError::RetentionNotPermitted);
        }
        Ok(())
    }

    /// Enforce the grant's geographic-resolution floor.
    ///
    /// # Errors
    /// Returns [`ConsentError::GeoResolutionNotPermitted`] when the requested
    /// resolution is finer than the durable grant permits.
    pub const fn authorize_geo_resolution(&self, resolution: u8) -> Result<(), ConsentError> {
        if resolution < self.min_geo_resolution {
            Err(ConsentError::GeoResolutionNotPermitted)
        } else {
            Ok(())
        }
    }

    /// Enforce the grant's retention duration.
    ///
    /// # Errors
    /// Returns [`ConsentError::RetentionNotPermitted`] when the requested
    /// duration exceeds the durable grant.
    pub const fn authorize_retention(&self, days: u16) -> Result<(), ConsentError> {
        if self.retention_days == 0 || days > self.retention_days {
            Err(ConsentError::RetentionNotPermitted)
        } else {
            Ok(())
        }
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

#[derive(Clone, Debug)]
struct ActiveConsent {
    token: ConsentCapabilityToken,
    expiry_secs: u32,
}

type ActiveConsentSessions = HashMap<(TimelineId, EntityId, EntityId, u64), ActiveConsent>;

/// Host-owned reservation that serializes a durable revocation with protected
/// appends using the same [`ConsentAuthority`] state.
///
/// A reservation temporarily fences its session before the host begins the
/// durable append. The host must commit it after that append succeeds or
/// abort it when the append fails.
#[derive(Debug)]
pub struct ConsentRevocationReservation {
    active: Arc<Mutex<ActiveConsentSessions>>,
    authority_id: u64,
    timeline_id: TimelineId,
    subject_id: EntityId,
    grantee_id: EntityId,
    grant_seq: u64,
    previous_fence_seq: u64,
    pending_fence_seq: u64,
    fence_seq: u64,
    completed: bool,
}

impl ConsentRevocationReservation {
    fn rollback(&mut self) {
        if self.completed {
            return;
        }
        let key = (
            self.timeline_id,
            self.subject_id,
            self.grantee_id,
            self.grant_seq,
        );
        let mut sessions = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(active) = sessions.get_mut(&key) {
            if active.token.fence_seq == self.pending_fence_seq {
                active.token.fence_seq = self.previous_fence_seq;
            }
        }
        drop(sessions);
        self.completed = true;
    }

    /// Publish the durable revocation fence after its Event append succeeds.
    ///
    /// # Errors
    /// Returns [`ConsentError::NoConsent`] when the reserved session has already
    /// changed or disappeared. The reservation then rolls back on drop unless
    /// the fence was published successfully.
    pub fn commit_durable(mut self) -> Result<(), ConsentError> {
        let key = (
            self.timeline_id,
            self.subject_id,
            self.grantee_id,
            self.grant_seq,
        );
        let mut sessions = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(active) = sessions.get_mut(&key) else {
            return Err(ConsentError::NoConsent);
        };
        if active.token.fence_seq != self.pending_fence_seq {
            return Err(ConsentError::NoConsent);
        }
        active.token.fence_seq = self.fence_seq;
        drop(sessions);
        self.completed = true;
        Ok(())
    }

    /// Abort a durable revocation that was not appended.
    pub fn abort_durable(mut self) {
        self.rollback();
    }
}

impl Drop for ConsentRevocationReservation {
    fn drop(&mut self) {
        self.rollback();
    }
}

/// Host-owned authority that issues and invalidates consent capabilities.
///
/// Its identity and active sessions are private. A capability minted by a
/// different authority therefore fails validation against this authority.
#[derive(Clone)]
pub struct ConsentAuthority {
    authority_id: u64,
    active: Arc<Mutex<ActiveConsentSessions>>,
}

static NEXT_CONSENT_AUTHORITY_ID: AtomicU64 = AtomicU64::new(1);

impl Default for ConsentAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsentAuthority {
    /// Create a host-owned authority with private capability session state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            authority_id: NEXT_CONSENT_AUTHORITY_ID.fetch_add(1, Ordering::Relaxed),
            active: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record a durably committed grant bound to one Timeline.
    #[must_use]
    pub fn record_grant_on_timeline(
        &self,
        timeline_id: TimelineId,
        grant: &ConsentGranted,
    ) -> ConsentCapabilityToken {
        self.record_grant_with_timeline(timeline_id, grant)
    }

    fn record_grant_with_timeline(
        &self,
        timeline_id: TimelineId,
        grant: &ConsentGranted,
    ) -> ConsentCapabilityToken {
        let token = ConsentCapabilityToken {
            authority_id: self.authority_id,
            timeline_id,
            subject_id: grant.subject_id,
            grantee_id: grant.grantee_id,
            modalities: grant.modalities,
            min_geo_resolution: grant.min_geo_resolution,
            fork_permitted: grant.fork_permitted,
            export_permitted: grant.export_permitted,
            retention_days: grant.retention_days,
            grant_seq: grant.grant_seq,
            fence_seq: u64::MAX,
        };
        let key = (
            timeline_id,
            grant.subject_id,
            grant.grantee_id,
            grant.grant_seq,
        );
        let active = ActiveConsent {
            token: token.clone(),
            expiry_secs: grant.expiry_secs,
        };
        let mut sessions = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions.insert(key, active);
        token
    }

    /// Confirm that a durable revocation names an active session on a Timeline.
    ///
    /// # Errors
    /// Returns [`ConsentError::NoConsent`] when no active session matches.
    pub fn validate_revocation_on_timeline(
        &self,
        timeline_id: TimelineId,
        revocation: &ConsentRevoked,
    ) -> Result<(), ConsentError> {
        self.validate_revocation_with_timeline(timeline_id, revocation)
    }

    /// Reserve a durable revocation and fence protected appends immediately.
    ///
    /// The returned reservation must be passed to
    /// [`Self::commit_revocation`] after the Gateway has durably appended the
    /// revocation, or to [`Self::abort_revocation`] when that append fails.
    /// While the reservation is active, protected appends for this exact
    /// session fail closed even though the durable Event is not yet present.
    ///
    /// # Errors
    /// Returns [`ConsentError::NoConsent`] when the session is absent and
    /// [`ConsentError::Revoked`] when another revocation already fenced it.
    pub fn begin_revocation_on_timeline(
        &self,
        timeline_id: TimelineId,
        revocation: &ConsentRevoked,
    ) -> Result<ConsentRevocationReservation, ConsentError> {
        let pending_fence_seq = revocation.fence_seq.saturating_sub(1);
        let key = (
            timeline_id,
            revocation.subject_id,
            revocation.grantee_id,
            revocation.grant_seq,
        );
        let mut sessions = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(active) = sessions.get_mut(&key) else {
            return Err(ConsentError::NoConsent);
        };
        if active.token.fence_seq <= revocation.fence_seq {
            return Err(ConsentError::Revoked);
        }
        let previous_fence_seq = active.token.fence_seq;
        active.token.fence_seq = pending_fence_seq;
        let reservation = ConsentRevocationReservation {
            active: Arc::clone(&self.active),
            authority_id: self.authority_id,
            timeline_id,
            subject_id: revocation.subject_id,
            grantee_id: revocation.grantee_id,
            grant_seq: revocation.grant_seq,
            previous_fence_seq,
            pending_fence_seq,
            fence_seq: revocation.fence_seq,
            completed: false,
        };
        drop(sessions);
        Ok(reservation)
    }

    /// Publish a successfully appended revocation's durable fence.
    ///
    /// # Errors
    /// Returns [`ConsentError::NoConsent`] when the reservation belongs to a
    /// different authority or the reserved session no longer exists.
    pub fn commit_revocation(
        &self,
        reservation: ConsentRevocationReservation,
    ) -> Result<(), ConsentError> {
        if reservation.authority_id != self.authority_id {
            return Err(ConsentError::NoConsent);
        }
        reservation.commit_durable()
    }

    /// Abort a failed durable revocation append and restore its prior fence.
    ///
    /// A later direct revocation or grant publication is preserved if it has
    /// already changed the session while the reservation was being resolved.
    pub fn abort_revocation(&self, reservation: ConsentRevocationReservation) {
        if reservation.authority_id != self.authority_id {
            return;
        }
        reservation.abort_durable();
    }

    fn validate_revocation_with_timeline(
        &self,
        timeline_id: TimelineId,
        revocation: &ConsentRevoked,
    ) -> Result<(), ConsentError> {
        let key = (
            timeline_id,
            revocation.subject_id,
            revocation.grantee_id,
            revocation.grant_seq,
        );
        let active = {
            let sessions = self
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sessions.contains_key(&key)
        };
        if !active {
            return Err(ConsentError::NoConsent);
        }
        Ok(())
    }

    /// Apply a durable revocation to its matching Timeline-bound session.
    ///
    /// # Errors
    /// Returns [`ConsentError::NoConsent`] when no active session matches.
    pub fn record_revocation_on_timeline(
        &self,
        timeline_id: TimelineId,
        revocation: &ConsentRevoked,
    ) -> Result<(), ConsentError> {
        self.record_revocation_with_timeline(timeline_id, revocation)
    }

    fn record_revocation_with_timeline(
        &self,
        timeline_id: TimelineId,
        revocation: &ConsentRevoked,
    ) -> Result<(), ConsentError> {
        let key = (
            timeline_id,
            revocation.subject_id,
            revocation.grantee_id,
            revocation.grant_seq,
        );
        match self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&key)
        {
            Some(active) => {
                active.token.fence_seq = active.token.fence_seq.min(revocation.fence_seq);
            }
            None => {
                return Err(ConsentError::NoConsent);
            }
        }
        Ok(())
    }

    /// Revalidate an exact host session against its bound Timeline.
    ///
    /// # Errors
    /// Returns [`ConsentError::NoConsent`] for a mismatched authority, token,
    /// or Timeline; otherwise returns revocation or expiry errors.
    pub fn validate_on_timeline(
        &self,
        timeline_id: TimelineId,
        token: &ConsentCapabilityToken,
        timeline_head: u64,
        now_secs: u64,
    ) -> Result<(), ConsentError> {
        self.validate_with_timeline(timeline_id, token, timeline_head, now_secs)
    }

    fn validate_with_timeline(
        &self,
        timeline_id: TimelineId,
        token: &ConsentCapabilityToken,
        timeline_head: u64,
        now_secs: u64,
    ) -> Result<(), ConsentError> {
        if token.authority_id != self.authority_id {
            return Err(ConsentError::NoConsent);
        }
        if token.timeline_id != timeline_id {
            return Err(ConsentError::NoConsent);
        }
        let key = (
            timeline_id,
            token.subject_id,
            token.grantee_id,
            token.grant_seq,
        );
        let sessions = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::validate_from_sessions(&sessions, &key, token, timeline_head, now_secs)
    }

    fn validate_from_sessions(
        sessions: &ActiveConsentSessions,
        key: &(TimelineId, EntityId, EntityId, u64),
        token: &ConsentCapabilityToken,
        timeline_head: u64,
        now_secs: u64,
    ) -> Result<(), ConsentError> {
        let Some(active) = sessions.get(key) else {
            return Err(ConsentError::NoConsent);
        };
        if active.token != *token || !active.token.is_valid_at(timeline_head) {
            return Err(ConsentError::Revoked);
        }
        if active.expiry_secs != 0 && now_secs >= u64::from(active.expiry_secs) {
            return Err(ConsentError::Expired);
        }
        Ok(())
    }

    /// Replay a Timeline-bound slice of durable consent history.
    ///
    /// Existing sessions are retained so callers may replay history
    /// incrementally. The decoded slice is applied atomically: malformed or
    /// unmatched history leaves the current sessions unchanged.
    ///
    /// # Errors
    /// Returns [`ConsentCodecError`] when a durable consent payload is invalid
    /// or a revocation has no matching grant in the same Timeline history.
    pub fn restore_from_history(
        &self,
        timeline_id: TimelineId,
        events: &[crate::event::Event],
    ) -> Result<(), ConsentCodecError> {
        if events.len() > MAX_CONSENT_HISTORY_EVENTS {
            return Err(ConsentCodecError::HistoryTooLong {
                count: events.len(),
            });
        }

        enum RestoredConsentEvent {
            Granted(ConsentGranted),
            Revoked(ConsentRevoked),
        }

        let mut decoded = Vec::with_capacity(events.len());
        for event in events {
            match event.event_type.as_str() {
                EVENT_TYPE_CONSENT_GRANTED_V1 => {
                    let grant = ConsentGranted::decode(&event.payload)?;
                    if event.entity != grant.subject_id || event.seq.as_u64() != grant.grant_seq {
                        return Err(ConsentCodecError::HistoryCoordinateMismatch);
                    }
                    decoded.push(RestoredConsentEvent::Granted(grant));
                }
                EVENT_TYPE_CONSENT_REVOKED_V1 => {
                    let revocation = ConsentRevoked::decode(&event.payload)?;
                    if event.entity != revocation.subject_id
                        || event.seq.as_u64() != revocation.fence_seq
                    {
                        return Err(ConsentCodecError::HistoryCoordinateMismatch);
                    }
                    decoded.push(RestoredConsentEvent::Revoked(revocation));
                }
                _ => {}
            }
        }

        {
            let mut sessions = self
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut restored = sessions.clone();
            for event in decoded {
                match event {
                    RestoredConsentEvent::Granted(grant) => {
                        let token = ConsentCapabilityToken {
                            authority_id: self.authority_id,
                            timeline_id,
                            subject_id: grant.subject_id,
                            grantee_id: grant.grantee_id,
                            modalities: grant.modalities,
                            min_geo_resolution: grant.min_geo_resolution,
                            fork_permitted: grant.fork_permitted,
                            export_permitted: grant.export_permitted,
                            retention_days: grant.retention_days,
                            grant_seq: grant.grant_seq,
                            fence_seq: u64::MAX,
                        };
                        restored.insert(
                            (
                                timeline_id,
                                grant.subject_id,
                                grant.grantee_id,
                                grant.grant_seq,
                            ),
                            ActiveConsent {
                                token,
                                expiry_secs: grant.expiry_secs,
                            },
                        );
                    }
                    RestoredConsentEvent::Revoked(revocation) => {
                        let key = (
                            timeline_id,
                            revocation.subject_id,
                            revocation.grantee_id,
                            revocation.grant_seq,
                        );
                        let Some(active) = restored.get_mut(&key) else {
                            return Err(ConsentCodecError::UnmatchedRevocation);
                        };
                        active.token.fence_seq = active.token.fence_seq.min(revocation.fence_seq);
                    }
                }
            }
            *sessions = restored;
        }

        Ok(())
    }
}

/// Plugin seam for consent enforcement (ADR-039).
///
/// Equivalent to `GeoLocationAdmissionStore` - prevents plugins from
/// accessing sensitive event types without a valid, non-revoked consent grant.
pub trait ConsentGate: Send + Sync {
    /// Check whether `subject` holds an active, non-revoked, non-expired consent grant
    /// that covers `event_type` at `timeline_head`. Known `geo.`/`location.`,
    /// `persona.`, `model.`, and `export.` event families also require the
    /// corresponding modality bit in the grant.
    ///
    /// Returns [`ConsentError::ConsentEventsForbidden`] for `consent.*` event
    /// types (Gateway-only per ADR-024 section 2).
    ///
    /// Returns [`ConsentError::Revoked`] if `token.fence_seq <= timeline_head`.
    /// Returns [`ConsentError::ModalityNotGranted`] when a known event family
    /// is not covered by the grant's modality bitmask.
    ///
    /// # Errors
    /// Returns a [`ConsentError`] describing why consent was not granted.
    fn check_consent(
        &self,
        timeline_id: TimelineId,
        subject: EntityId,
        event_type: &Kind,
        timeline_head: u64,
        now_secs: u64,
    ) -> Result<ConsentCapabilityToken, ConsentError>;

    /// Authorize one emitted Event at the current operation fence.
    ///
    /// Hosts call this seam for every draft, including ordinary events. A
    /// concrete authority may classify an ordinary event as public, but the
    /// classification is made by the host-owned gate rather than by the
    /// registry's operation path.
    ///
    /// # Errors
    /// Returns a [`ConsentError`] when the host policy rejects the event.
    fn authorize_event(
        &self,
        timeline_id: TimelineId,
        subject: EntityId,
        event_type: &Kind,
        timeline_head: u64,
        now_secs: u64,
    ) -> Result<(), ConsentError> {
        self.check_consent(timeline_id, subject, event_type, timeline_head, now_secs)
            .map(|_| ())
    }

    /// Authorize a projection read for the exact subject carried by a token.
    /// Public operation contexts have no token and therefore cannot use this
    /// seam. Hosts must apply it before materializing projection state.
    ///
    /// # Errors
    /// Returns a consent-fence error when the token is not current at the read
    /// boundary.
    fn authorize_projection(
        &self,
        timeline_id: TimelineId,
        subject: EntityId,
        timeline_head: u64,
        now_secs: u64,
        token: &ConsentCapabilityToken,
    ) -> Result<(), ConsentError> {
        if token.subject_id() != subject {
            return Err(ConsentError::NoConsent);
        }
        self.validate_token(timeline_id, token, timeline_head, now_secs)
    }

    /// Hold the host's consent fence while the caller performs its durable
    /// append. Authorities that share revocation state with this gate override
    /// this method so revocation cannot interleave between validation and the
    /// append closure.
    ///
    /// # Errors
    /// Returns the consent-fence error without invoking `append` when the
    /// capability is no longer valid.
    fn with_token_fence(
        &self,
        timeline_id: TimelineId,
        token: &ConsentCapabilityToken,
        timeline_head: u64,
        now_secs: u64,
        append: &mut dyn FnMut(),
    ) -> Result<(), ConsentError> {
        self.validate_token(timeline_id, token, timeline_head, now_secs)?;
        append();
        Ok(())
    }

    /// Revalidate a previously issued capability at an operation or commit fence.
    ///
    /// # Errors
    /// Returns [`ConsentError::NoConsent`] unless the gate implements this
    /// protected-token validation seam.
    fn validate_token(
        &self,
        timeline_id: TimelineId,
        token: &ConsentCapabilityToken,
        timeline_head: u64,
        now_secs: u64,
    ) -> Result<(), ConsentError> {
        let _ = (timeline_id, token, timeline_head, now_secs);
        Err(ConsentError::NoConsent)
    }
}

impl ConsentGate for ConsentAuthority {
    fn check_consent(
        &self,
        timeline_id: TimelineId,
        subject: EntityId,
        event_type: &Kind,
        timeline_head: u64,
        now_secs: u64,
    ) -> Result<ConsentCapabilityToken, ConsentError> {
        if is_consent_event_type(event_type) {
            return Err(ConsentError::ConsentEventsForbidden);
        }
        let candidate = {
            let sessions = self
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sessions
                .values()
                .find(|active| {
                    active.token.timeline_id == timeline_id
                        && active.token.subject_id == subject
                        && active.token.is_valid_at(timeline_head)
                })
                .map(|active| (active.token.clone(), active.expiry_secs))
        };
        let required_modality = required_modality_for_event(event_type);
        match candidate {
            Some((_, expiry_secs)) if expiry_secs != 0 && now_secs >= u64::from(expiry_secs) => {
                Err(ConsentError::Expired)
            }
            Some((active, _))
                if required_modality == MODALITY_EXPORT && !active.export_permitted =>
            {
                Err(ConsentError::ExportNotPermitted)
            }
            Some((active, _))
                if event_type.as_str().starts_with("timeline.fork.") && !active.fork_permitted =>
            {
                Err(ConsentError::ForkNotPermitted)
            }
            Some((active, _))
                if event_type.as_str().starts_with("retention.") && active.retention_days == 0 =>
            {
                Err(ConsentError::RetentionNotPermitted)
            }
            Some((active, _))
                if required_modality != 0
                    && active.modalities & required_modality != required_modality =>
            {
                Err(ConsentError::ModalityNotGranted)
            }
            Some((active, _)) => Ok(active),
            None => Err(ConsentError::NoConsent),
        }
    }

    fn validate_token(
        &self,
        timeline_id: TimelineId,
        token: &ConsentCapabilityToken,
        timeline_head: u64,
        now_secs: u64,
    ) -> Result<(), ConsentError> {
        self.validate_on_timeline(timeline_id, token, timeline_head, now_secs)
    }

    fn with_token_fence(
        &self,
        timeline_id: TimelineId,
        token: &ConsentCapabilityToken,
        timeline_head: u64,
        now_secs: u64,
        append: &mut dyn FnMut(),
    ) -> Result<(), ConsentError> {
        if token.authority_id != self.authority_id || token.timeline_id != timeline_id {
            return Err(ConsentError::NoConsent);
        }
        let key = (
            timeline_id,
            token.subject_id,
            token.grantee_id,
            token.grant_seq,
        );
        let sessions = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::validate_from_sessions(&sessions, &key, token, timeline_head, now_secs)?;
        append();
        Ok(())
    }

    fn authorize_event(
        &self,
        timeline_id: TimelineId,
        subject: EntityId,
        event_type: &Kind,
        timeline_head: u64,
        now_secs: u64,
    ) -> Result<(), ConsentError> {
        if is_consent_event_type(event_type) {
            return Err(ConsentError::ConsentEventsForbidden);
        }
        if required_modality_for_event(event_type) != 0
            || event_type.as_str().starts_with("timeline.fork.")
            || event_type.as_str().starts_with("retention.")
        {
            // Public operation contexts do not carry a caller capability. A
            // sensitive event therefore cannot borrow whichever active grant
            // happens to match its entity; callers must use a protected API
            // with the exact host-issued token.
            return Err(ConsentError::NoConsent);
        }
        let _ = (timeline_id, subject, timeline_head, now_secs);
        Ok(())
    }
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clock::WallTime,
        crypto::Hash,
        event::{Event, Kind, SchemaVersion},
        ids::{EntityId, EventId},
    };

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        #[cfg_attr(coverage_nightly, coverage(off))]
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
        #[cfg_attr(coverage_nightly, coverage(off))]
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

    fn record_test_grant(
        authority: &ConsentAuthority,
        grant: &ConsentGranted,
    ) -> (TimelineId, ConsentCapabilityToken) {
        let timeline = TimelineId::new();
        let token = authority.record_grant_on_timeline(timeline, grant);
        (timeline, token)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn the_entire_gateway_consent_namespace_is_reserved() {
        assert!(is_consent_event_type(&Kind::new(
            EVENT_TYPE_CONSENT_GRANTED_V1
        )));
        assert!(is_consent_event_type(&Kind::new(
            EVENT_TYPE_CONSENT_REVOKED_V1
        )));
        assert!(is_consent_event_type(&Kind::new("consent.granted.v2")));
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
    fn consent_granted_accepts_a_purpose_at_the_documented_byte_limit() {
        let mut grant = sample_granted();
        grant.purpose = "x".repeat(MAX_PURPOSE_BYTES);

        let encoded = grant.encode().test_ok();
        assert_eq!(ConsentGranted::decode(&encoded).test_ok(), grant);
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

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_granted_decoding_rejects_an_excessive_geo_resolution() {
        let grant = sample_granted();
        let bytes = grant.encode().test_ok().as_slice().to_vec();
        let mut value: Value = ciborium::from_reader(&mut std::io::Cursor::new(bytes)).test_ok();
        if let Value::Array(items) = &mut value {
            items[6] = Value::Integer(2_u8.into());
        }
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded).test_ok();

        assert_eq!(
            ConsentGranted::decode(&CanonicalBytes::from_vec(encoded)).test_err(),
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
        let authority = ConsentAuthority::new();
        let (_, token) = record_test_grant(&authority, &g);
        assert!(token.is_valid_at(u64::MAX - 1));
        assert!(!token.is_valid_at(u64::MAX));
        assert_eq!(token.grant_seq, g.grant_seq);
        assert_eq!(token.modalities, g.modalities);
        assert_eq!(token.subject_id, g.subject_id);
        assert_eq!(token.grantee_id, g.grantee_id);
        assert_eq!(token.min_geo_resolution(), g.min_geo_resolution);
        assert_eq!(token.fork_permitted(), g.fork_permitted);
        assert_eq!(token.export_permitted(), g.export_permitted);
        assert_eq!(token.retention_days(), g.retention_days);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn token_is_valid_before_fence_seq() {
        let g = sample_granted();
        let authority = ConsentAuthority::new();
        let (_, token) = record_test_grant(&authority, &g);
        assert!(token.is_valid_at(0));
        assert!(token.is_valid_at(u64::MAX - 1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn token_is_invalid_at_or_after_fence_seq() {
        let g = sample_granted();
        let authority = ConsentAuthority::new();
        let (_, mut token) = record_test_grant(&authority, &g);
        let mut revocation = sample_revoked(&g);
        revocation.fence_seq = 100;
        token.invalidate_with(&revocation).test_ok();
        assert!(!token.is_valid_at(100));
        assert!(!token.is_valid_at(200));
        assert!(token.is_valid_at(99));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn matching_revocation_only_tightens_a_token_fence() {
        let grant = sample_granted();
        let authority = ConsentAuthority::new();
        let (_, mut token) = record_test_grant(&authority, &grant);
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
        let authority = ConsentAuthority::new();
        let (_, mut token) = record_test_grant(&authority, &grant);
        let mut revocation = sample_revoked(&grant);
        revocation.grant_seq += 1;
        assert_eq!(
            token.invalidate_with(&revocation),
            Err(ConsentError::NoConsent)
        );
        assert!(token.is_valid_at(u64::MAX - 1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn revocation_must_match_every_token_identity_component() {
        let grant = sample_granted();
        let authority = ConsentAuthority::new();
        let (_, mut token) = record_test_grant(&authority, &grant);

        let mut wrong_subject = sample_revoked(&grant);
        wrong_subject.subject_id = EntityId::new();
        assert_eq!(
            token.clone().invalidate_with(&wrong_subject),
            Err(ConsentError::NoConsent)
        );

        let mut wrong_grantee = sample_revoked(&grant);
        wrong_grantee.grantee_id = EntityId::new();
        assert_eq!(
            token.invalidate_with(&wrong_grantee),
            Err(ConsentError::NoConsent)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn host_authority_revalidates_its_exact_session_at_expiry_and_revocation_fences() {
        let authority = ConsentAuthority::new();
        let mut grant = sample_granted();
        grant.expiry_secs = 20;
        let (timeline, token) = record_test_grant(&authority, &grant);

        assert_eq!(token.grant_seq(), grant.grant_seq);

        assert!(authority
            .validate_on_timeline(timeline, &token, 1, 19)
            .is_ok());
        assert_eq!(
            authority.validate_on_timeline(timeline, &token, 1, 20),
            Err(ConsentError::Expired)
        );
        assert_eq!(
            ConsentAuthority::new().validate_on_timeline(timeline, &token, 1, 19),
            Err(ConsentError::NoConsent)
        );

        let revocation = ConsentRevoked {
            subject_id: grant.subject_id,
            grantee_id: grant.grantee_id,
            grant_seq: grant.grant_seq,
            fence_seq: 2,
        };
        assert!(authority
            .validate_revocation_on_timeline(timeline, &revocation)
            .is_ok());
        assert!(authority
            .record_revocation_on_timeline(timeline, &revocation)
            .is_ok());
        assert_eq!(
            authority.validate_on_timeline(timeline, &token, 2, 19),
            Err(ConsentError::Revoked)
        );
        assert_eq!(
            authority.validate_revocation_on_timeline(
                timeline,
                &ConsentRevoked {
                    grant_seq: grant.grant_seq + 1,
                    ..revocation
                },
            ),
            Err(ConsentError::NoConsent)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn host_authority_rejects_a_changed_token_even_when_the_active_token_is_unfenced() {
        let authority = ConsentAuthority::new();
        let grant = sample_granted();
        let (timeline, token) = record_test_grant(&authority, &grant);
        let mut revocation = sample_revoked(&grant);
        revocation.fence_seq = 0;
        authority
            .record_revocation_on_timeline(timeline, &revocation)
            .test_ok();

        assert_eq!(
            authority.validate_on_timeline(timeline, &token, 0, 0),
            Err(ConsentError::Revoked)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn default_authority_fails_closed_for_an_unrecorded_foreign_session() {
        let grant = sample_granted();
        let authority = ConsentAuthority::new();
        let (timeline, token) = record_test_grant(&authority, &grant);
        assert_eq!(
            ConsentAuthority::default().validate_on_timeline(timeline, &token, 0, 0),
            Err(ConsentError::NoConsent)
        );
    }

    // -- ConsentGate --

    struct TestGate {
        token: ConsentCapabilityToken,
        fence_seq: u64,
    }

    impl ConsentGate for TestGate {
        fn check_consent(
            &self,
            _timeline_id: TimelineId,
            _subject: EntityId,
            event_type: &Kind,
            timeline_head: u64,
            _now_secs: u64,
        ) -> Result<ConsentCapabilityToken, ConsentError> {
            if event_type.as_str().starts_with("consent.") {
                return Err(ConsentError::ConsentEventsForbidden);
            }
            if self.fence_seq <= timeline_head {
                return Err(ConsentError::Revoked);
            }
            Ok(self.token.clone())
        }
    }

    fn test_gate(fence_seq: u64) -> TestGate {
        let g = sample_granted();
        let authority = ConsentAuthority::new();
        let (_, token) = record_test_grant(&authority, &g);
        TestGate { token, fence_seq }
    }

    impl TestGate {
        fn timeline(&self) -> TimelineId {
            self.token.timeline_id()
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_allows_non_consent_event_within_fence() {
        let gate = test_gate(u64::MAX);
        assert!(gate
            .check_consent(
                gate.timeline(),
                EntityId::new(),
                &Kind::new("world.observation.v1"),
                50,
                0,
            )
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_forbids_consent_granted_events() {
        let gate = test_gate(u64::MAX);
        assert_eq!(
            gate.check_consent(
                gate.timeline(),
                EntityId::new(),
                &Kind::new(EVENT_TYPE_CONSENT_GRANTED_V1),
                0,
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
                gate.timeline(),
                EntityId::new(),
                &Kind::new(EVENT_TYPE_CONSENT_REVOKED_V1),
                0,
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
                gate.timeline(),
                EntityId::new(),
                &Kind::new("world.observation.v1"),
                100, // head == fence -> invalid
                0
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
            .check_consent(
                gate.timeline(),
                EntityId::new(),
                &Kind::new("persona.update.v1"),
                99,
                0,
            )
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn timeline_bound_authority_rejects_wrong_subject_timeline_and_session() {
        let authority = ConsentAuthority::new();
        let timeline = TimelineId::new();
        let grant = sample_granted();
        let token = authority.record_grant_on_timeline(timeline, &grant);

        assert!(authority
            .check_consent(
                timeline,
                grant.subject_id,
                &Kind::new("world.observation.v1"),
                0,
                0,
            )
            .is_ok());
        assert_eq!(
            authority.check_consent(
                TimelineId::new(),
                grant.subject_id,
                &Kind::new("world.observation.v1"),
                0,
                0,
            ),
            Err(ConsentError::NoConsent)
        );
        assert_eq!(
            authority.check_consent(
                timeline,
                EntityId::new(),
                &Kind::new("world.observation.v1"),
                0,
                0,
            ),
            Err(ConsentError::NoConsent)
        );

        let mut missing = token;
        missing.grant_seq += 1;
        assert_eq!(
            authority.validate_on_timeline(timeline, &missing, 0, 0),
            Err(ConsentError::NoConsent)
        );

        let wrong_timeline_revocation = sample_revoked(&grant);
        assert_eq!(
            authority.record_revocation_on_timeline(TimelineId::new(), &wrong_timeline_revocation,),
            Err(ConsentError::NoConsent)
        );

        let wrong_session_revocation = ConsentRevoked {
            grant_seq: grant.grant_seq + 1,
            ..wrong_timeline_revocation
        };
        assert_eq!(
            authority.record_revocation_on_timeline(timeline, &wrong_session_revocation),
            Err(ConsentError::NoConsent)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn revocation_reservation_blocks_protected_append_until_commit() {
        let authority = ConsentAuthority::new();
        let timeline = TimelineId::new();
        let grant = sample_granted();
        let token = authority.record_grant_on_timeline(timeline, &grant);
        let revocation = ConsentRevoked {
            subject_id: grant.subject_id,
            grantee_id: grant.grantee_id,
            grant_seq: grant.grant_seq,
            fence_seq: 1,
        };
        let started = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        let revoking_authority = authority.clone();
        let revoking_started = started.clone();
        let revoking_release = release.clone();
        let handle = std::thread::spawn(move || {
            let reservation = revoking_authority
                .begin_revocation_on_timeline(timeline, &revocation)
                .test_ok();
            revoking_started.wait();
            revoking_release.wait();
            revoking_authority.commit_revocation(reservation).test_ok();
        });

        started.wait();
        let mut append_count = 0;
        let error = authority
            .with_token_fence(timeline, &token, 0, 0, &mut || append_count += 1)
            .test_err();
        assert_eq!(error, ConsentError::Revoked);
        assert_eq!(append_count, 0);
        release.wait();
        assert!(handle.join().is_ok());
        assert_eq!(
            authority.validate_on_timeline(timeline, &token, 1, 0),
            Err(ConsentError::Revoked)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cancelled_revocation_future_restores_the_capability_fence() {
        use std::future::Future as _;

        let authority = ConsentAuthority::new();
        let timeline = TimelineId::new();
        let grant = sample_granted();
        let token = authority.record_grant_on_timeline(timeline, &grant);
        let revocation = ConsentRevoked {
            subject_id: grant.subject_id,
            grantee_id: grant.grantee_id,
            grant_seq: grant.grant_seq,
            fence_seq: 1,
        };
        let future_authority = authority.clone();
        let mut future = Box::pin(async move {
            let reservation = future_authority
                .begin_revocation_on_timeline(timeline, &revocation)
                .test_ok();
            std::future::pending::<()>().await;
            future_authority.commit_revocation(reservation).test_ok();
        });
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        assert!(matches!(
            future.as_mut().poll(&mut context),
            std::task::Poll::Pending
        ));
        drop(future);

        assert!(authority
            .validate_on_timeline(timeline, &token, 0, 0)
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn restore_from_history_rebuilds_and_revokes_timeline_sessions() {
        fn event(event_type: &str, payload: CanonicalBytes, entity: EntityId, seq: u64) -> Event {
            Event {
                id: EventId::new(),
                entity,
                event_type: Kind::new(event_type),
                payload,
                wall_time: WallTime::from_micros(1),
                seq: crate::clock::Seq::from_u64(seq),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: None,
                payload_hash: Hash::from_bytes([0; 32]),
            }
        }

        let authority = ConsentAuthority::new();
        let timeline = TimelineId::new();
        let grant = sample_granted();
        let grant_payload = grant.encode().test_ok();
        let revocation = sample_revoked(&grant);
        let revocation_payload = revocation.encode().test_ok();

        authority
            .restore_from_history(
                timeline,
                &[
                    event(
                        EVENT_TYPE_CONSENT_GRANTED_V1,
                        grant_payload,
                        grant.subject_id,
                        grant.grant_seq,
                    ),
                    event(
                        "world.observation.v1",
                        CanonicalBytes::from_static(b"ignored"),
                        EntityId::new(),
                        1,
                    ),
                ],
            )
            .test_ok();
        let token = authority
            .check_consent(
                timeline,
                grant.subject_id,
                &Kind::new("world.observation.v1"),
                0,
                0,
            )
            .test_ok();

        authority
            .restore_from_history(
                timeline,
                &[event(
                    EVENT_TYPE_CONSENT_REVOKED_V1,
                    revocation_payload,
                    revocation.subject_id,
                    revocation.fence_seq,
                )],
            )
            .test_ok();
        assert_eq!(
            authority.validate_on_timeline(timeline, &token, 100, 0),
            Err(ConsentError::Revoked)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn restore_from_history_rejects_an_unmatched_revocation() {
        fn event(payload: CanonicalBytes, entity: EntityId, seq: u64) -> Event {
            Event {
                id: EventId::new(),
                entity,
                event_type: Kind::new(EVENT_TYPE_CONSENT_REVOKED_V1),
                payload,
                wall_time: WallTime::from_micros(1),
                seq: crate::clock::Seq::from_u64(seq),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: None,
                payload_hash: Hash::from_bytes([0; 32]),
            }
        }

        let grant = sample_granted();
        let timeline = TimelineId::new();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(timeline, &grant);
        let mut revocation = sample_revoked(&grant);
        revocation.grant_seq = revocation.grant_seq.saturating_add(1);
        let error = authority
            .restore_from_history(
                timeline,
                &[event(
                    revocation.encode().test_ok(),
                    revocation.subject_id,
                    revocation.fence_seq,
                )],
            )
            .test_err();
        assert_eq!(error, ConsentCodecError::UnmatchedRevocation);
        assert!(authority
            .validate_on_timeline(timeline, &token, 0, 0)
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn restore_from_history_rejects_coordinate_mismatches() {
        fn event(event_type: &str, payload: CanonicalBytes, entity: EntityId, seq: u64) -> Event {
            Event {
                id: EventId::new(),
                entity,
                event_type: Kind::new(event_type),
                payload,
                wall_time: WallTime::from_micros(1),
                seq: crate::clock::Seq::from_u64(seq),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: None,
                payload_hash: Hash::from_bytes([0; 32]),
            }
        }

        let timeline = TimelineId::new();
        let grant = sample_granted();
        let grant_payload = grant.encode().test_ok();
        assert_eq!(
            ConsentAuthority::new()
                .restore_from_history(
                    timeline,
                    &[event(
                        EVENT_TYPE_CONSENT_GRANTED_V1,
                        grant_payload,
                        EntityId::new(),
                        grant.grant_seq,
                    )],
                )
                .test_err(),
            ConsentCodecError::HistoryCoordinateMismatch
        );

        let authority = ConsentAuthority::new();
        let existing_timeline = TimelineId::new();
        let existing_grant = sample_granted();
        let existing_token = authority
            .record_grant_on_timeline(existing_timeline, &existing_grant);
        assert_eq!(
            authority
                .restore_from_history(
                    existing_timeline,
                    &[event(
                        EVENT_TYPE_CONSENT_GRANTED_V1,
                        existing_grant.encode().test_ok(),
                        EntityId::new(),
                        existing_grant.grant_seq,
                    )],
                )
                .test_err(),
            ConsentCodecError::HistoryCoordinateMismatch
        );
        assert!(authority
            .validate_on_timeline(existing_timeline, &existing_token, 0, 0)
            .is_ok());
        assert_eq!(
            authority
                .restore_from_history(
                    existing_timeline,
                    &[event(
                        EVENT_TYPE_CONSENT_GRANTED_V1,
                        CanonicalBytes::from_static(b"malformed"),
                        existing_grant.subject_id,
                        existing_grant.grant_seq,
                    )],
                )
                .test_err(),
            ConsentCodecError::CborError
        );
        assert!(authority
            .validate_on_timeline(existing_timeline, &existing_token, 0, 0)
            .is_ok());

        let revocation = sample_revoked(&grant);
        assert_eq!(
            ConsentAuthority::new()
                .restore_from_history(
                    timeline,
                    &[event(
                        EVENT_TYPE_CONSENT_REVOKED_V1,
                        revocation.encode().test_ok(),
                        revocation.subject_id,
                        revocation.fence_seq + 1,
                    )],
                )
                .test_err(),
            ConsentCodecError::HistoryCoordinateMismatch
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_enforces_known_event_modalities() {
        let authority = ConsentAuthority::new();
        let timeline = TimelineId::new();
        let mut grant = sample_granted();
        grant.modalities = MODALITY_LOCATION;
        let _token = authority.record_grant_on_timeline(timeline, &grant);

        assert_eq!(
            authority.check_consent(
                timeline,
                grant.subject_id,
                &Kind::new("persona.update.v1"),
                0,
                0,
            ),
            Err(ConsentError::ModalityNotGranted)
        );
        assert!(authority
            .check_consent(
                timeline,
                grant.subject_id,
                &Kind::new("geo.location.v1"),
                0,
                0,
            )
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_authorization_never_borrows_a_sensitive_grant() {
        let authority = ConsentAuthority::new();
        let timeline = TimelineId::new();
        let grant = sample_granted();
        let _token = authority.record_grant_on_timeline(timeline, &grant);

        assert_eq!(
            authority.authorize_event(
                timeline,
                grant.subject_id,
                &Kind::new("persona.update.v1"),
                0,
                0,
            ),
            Err(ConsentError::NoConsent)
        );
        assert_eq!(
            authority.authorize_event(
                timeline,
                grant.subject_id,
                &Kind::new(EVENT_TYPE_CONSENT_GRANTED_V1),
                0,
                0,
            ),
            Err(ConsentError::ConsentEventsForbidden)
        );
        assert!(authority
            .authorize_event(
                timeline,
                grant.subject_id,
                &Kind::new("driver.observation.v1"),
                0,
                0,
            )
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_token_enforces_durable_policy_flags() {
        let timeline = TimelineId::new();
        let authority = ConsentAuthority::new();
        let mut denied_grant = sample_granted();
        denied_grant.modalities = MODALITY_EXPORT;
        let denied_token = authority.record_grant_on_timeline(timeline, &denied_grant);
        assert_eq!(
            denied_token.authorize_event_type(&Kind::new("export.bundle.v1")),
            Err(ConsentError::ExportNotPermitted)
        );
        assert_eq!(
            authority.check_consent(
                timeline,
                denied_grant.subject_id,
                &Kind::new("export.bundle.v1"),
                0,
                0,
            ),
            Err(ConsentError::ExportNotPermitted)
        );

        let mut full_grant = sample_granted();
        full_grant.modalities =
            MODALITY_LOCATION | MODALITY_PERSONA | MODALITY_MODEL_FIT | MODALITY_EXPORT;
        full_grant.export_permitted = true;
        let full_token = authority.record_grant_on_timeline(timeline, &full_grant);
        assert!(full_token
            .authorize_event_type(&Kind::new("timeline.fork.v1"))
            .is_ok());
        assert!(full_token.authorize_geo_resolution(1).is_ok());
        assert!(full_token.authorize_retention(30).is_ok());
        assert!(authority
            .check_consent(
                timeline,
                full_grant.subject_id,
                &Kind::new("model.fit.v1"),
                0,
                0,
            )
            .is_ok());
        assert!(authority
            .check_consent(
                timeline,
                full_grant.subject_id,
                &Kind::new("export.bundle.v1"),
                0,
                0,
            )
            .is_ok());

        let mut constrained_grant = sample_granted();
        constrained_grant.fork_permitted = false;
        constrained_grant.min_geo_resolution = 1;
        constrained_grant.retention_days = 0;
        let constrained_token = authority.record_grant_on_timeline(timeline, &constrained_grant);
        assert_eq!(
            constrained_token.authorize_event_type(&Kind::new("timeline.fork.v1")),
            Err(ConsentError::ForkNotPermitted)
        );
        assert_eq!(
            constrained_token.authorize_geo_resolution(0),
            Err(ConsentError::GeoResolutionNotPermitted)
        );
        assert_eq!(
            constrained_token.authorize_retention(2),
            Err(ConsentError::RetentionNotPermitted)
        );
        assert_eq!(
            authority.check_consent(
                timeline,
                constrained_grant.subject_id,
                &Kind::new("retention.extend.v1"),
                0,
                0,
            ),
            Err(ConsentError::RetentionNotPermitted)
        );
        assert!(authority
            .check_consent(
                timeline,
                full_grant.subject_id,
                &Kind::new("location.coordinate.v1"),
                0,
                0,
            )
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_policy_and_projection_seams_fail_closed() {
        struct PermissiveGate;

        impl ConsentGate for PermissiveGate {
            fn check_consent(
                &self,
                _: TimelineId,
                _: EntityId,
                _: &Kind,
                _: u64,
                _: u64,
            ) -> Result<ConsentCapabilityToken, ConsentError> {
                Err(ConsentError::NoConsent)
            }

            fn validate_token(
                &self,
                _: TimelineId,
                _: &ConsentCapabilityToken,
                _: u64,
                _: u64,
            ) -> Result<(), ConsentError> {
                Ok(())
            }
        }

        let authority = ConsentAuthority::new();
        let timeline = TimelineId::new();
        let mut grant = sample_granted();
        grant.modalities = MODALITY_LOCATION;
        grant.fork_permitted = false;
        grant.retention_days = 0;
        let token = authority.record_grant_on_timeline(timeline, &grant);

        assert_eq!(
            token.authorize_event_type(&Kind::new("persona.update.v1")),
            Err(ConsentError::ModalityNotGranted)
        );
        assert_eq!(
            token.authorize_event_type(&Kind::new("retention.extend.v1")),
            Err(ConsentError::RetentionNotPermitted)
        );
        assert_eq!(
            authority.check_consent(
                timeline,
                grant.subject_id,
                &Kind::new("timeline.fork.v1"),
                0,
                0,
            ),
            Err(ConsentError::ForkNotPermitted)
        );
        assert_eq!(
            authority.check_consent(
                timeline,
                grant.subject_id,
                &Kind::new("consent.revoked.v1"),
                0,
                0,
            ),
            Err(ConsentError::ConsentEventsForbidden)
        );
        assert_eq!(
            ConsentGate::authorize_projection(&authority, timeline, EntityId::new(), 0, 0, &token,),
            Err(ConsentError::NoConsent)
        );
        let other_authority = ConsentAuthority::new();
        let other_token = other_authority.record_grant_on_timeline(timeline, &grant);
        assert_eq!(
            ConsentGate::with_token_fence(
                &authority,
                timeline,
                &other_token,
                0,
                0,
                &mut || {},
            ),
            Err(ConsentError::NoConsent)
        );

        let gate = PermissiveGate;
        let mut append_count = 0;
        ConsentGate::with_token_fence(&gate, timeline, &token, 0, 0, &mut || append_count += 1)
            .test_ok();
        assert_eq!(append_count, 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_reservation_error_seams_fail_closed() {
        let authority = ConsentAuthority::new();
        let timeline = TimelineId::new();
        let grant = sample_granted();
        let _token = authority.record_grant_on_timeline(timeline, &grant);

        let revocation = ConsentRevoked {
            subject_id: grant.subject_id,
            grantee_id: grant.grantee_id,
            grant_seq: grant.grant_seq,
            fence_seq: 1,
        };
        let reservation = authority
            .begin_revocation_on_timeline(timeline, &revocation)
            .test_ok();
        assert_eq!(
            authority
                .begin_revocation_on_timeline(timeline, &revocation)
                .test_err(),
            ConsentError::Revoked
        );
        authority.abort_revocation(reservation);

        let reservation = authority
            .begin_revocation_on_timeline(timeline, &revocation)
            .test_ok();
        let _token = authority.record_grant_on_timeline(timeline, &grant);
        assert_eq!(reservation.commit_durable(), Err(ConsentError::NoConsent));

        let reservation = authority
            .begin_revocation_on_timeline(timeline, &revocation)
            .test_ok();
        let other_authority = ConsentAuthority::new();
        assert_eq!(
            other_authority.commit_revocation(reservation),
            Err(ConsentError::NoConsent)
        );

        let reservation = authority
            .begin_revocation_on_timeline(timeline, &revocation)
            .test_ok();
        other_authority.abort_revocation(reservation);
        assert_eq!(
            authority.validate_revocation_on_timeline(TimelineId::new(), &revocation),
            Err(ConsentError::NoConsent)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_gate_rejects_an_expired_grant_at_check_time() {
        let authority = ConsentAuthority::new();
        let timeline = TimelineId::new();
        let mut grant = sample_granted();
        grant.expiry_secs = 10;
        let _token = authority.record_grant_on_timeline(timeline, &grant);

        assert_eq!(
            authority.check_consent(
                timeline,
                grant.subject_id,
                &Kind::new("world.observation.v1"),
                0,
                10,
            ),
            Err(ConsentError::Expired)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn restore_from_history_rejects_an_oversized_history_before_decoding() {
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("world.observation.v1"),
            payload: CanonicalBytes::from_static(b"ignored"),
            wall_time: WallTime::from_micros(1),
            seq: crate::clock::Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let events = vec![event; MAX_CONSENT_HISTORY_EVENTS + 1];

        assert_eq!(
            ConsentAuthority::new().restore_from_history(TimelineId::new(), &events),
            Err(ConsentCodecError::HistoryTooLong {
                count: MAX_CONSENT_HISTORY_EVENTS + 1,
            })
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn default_consent_gate_token_validation_fails_closed() {
        let gate = test_gate(u64::MAX);
        assert_eq!(
            gate.validate_token(gate.timeline(), &gate.token, 0, 0),
            Err(ConsentError::NoConsent)
        );
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
        assert!(!ConsentCodecError::UnmatchedRevocation
            .to_string()
            .is_empty());
        assert!(!ConsentCodecError::HistoryTooLong { count: 10_001 }
            .to_string()
            .is_empty());
        assert!(!ConsentCodecError::HistoryCoordinateMismatch
            .to_string()
            .is_empty());
        assert!(!format!("{}", ConsentCodecError::PurposeTooLong { size: 200 }).is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_error_display() {
        assert!(!ConsentError::NoConsent.to_string().is_empty());
        assert!(!ConsentError::Revoked.to_string().is_empty());
        assert!(!ConsentError::Expired.to_string().is_empty());
        assert!(!ConsentError::ModalityNotGranted.to_string().is_empty());
        assert!(!ConsentError::ExportNotPermitted.to_string().is_empty());
        assert!(!ConsentError::ForkNotPermitted.to_string().is_empty());
        assert!(!ConsentError::GeoResolutionNotPermitted
            .to_string()
            .is_empty());
        assert!(!ConsentError::RetentionNotPermitted.to_string().is_empty());
        assert!(!ConsentError::ConsentEventsForbidden.to_string().is_empty());
    }
}
