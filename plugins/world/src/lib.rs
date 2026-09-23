#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-world` — spatial + embodiment plugin with a swappable backend.
//!
//! Owns versioned World action, observation and configuration Events and entity kind `"world-body"`.
//! The built-in backend integrates a 3D pose without a Rapier dependency.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use num_traits::ToPrimitive;
use pos_core::{
    event::{CanonicalBytes, Event, Kind},
    ids::{EntityId, EventId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
    ActionApprover, ActionRejected, ProposedAction, WorldCoordinateV1, WorldTransformError,
    MAX_PROPOSED_ACTION_PAYLOAD_BYTES,
};
use pos_runtime::{
    Driver, DriverRecoveryEvidence, ObservationView, RecoveryEventHeader, RuntimeError, StepOutput,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The entity kind string for world bodies.
pub const ENTITY_KIND: &str = "world-body";

/// Versioned event type for world actions (ADR-047 v1).
pub const EVENT_TYPE_ACTION_V1: &str = "world.action.v1";

/// Versioned event type for world observations (ADR-047 v1).
pub const EVENT_TYPE_OBSERVATION_V1: &str = "world.observation.v1";

/// Versioned event type for world configuration (ADR-047 v1).
pub const EVENT_TYPE_CONFIG_V1: &str = "world.config.v1";

const MAGIC_WAC1: &[u8; 4] = b"WAC1";
const MAGIC_WOB1: &[u8; 4] = b"WOB1";
const MAGIC_WCF1: &[u8; 4] = b"WCF1";
const VERSION_V1: u8 = 1;
/// Maximum total payload for a `world.action.v1` event (ADR-047).
pub const MAX_ACTION_BYTES: usize = 4_096;
/// Maximum bytes for a sensor value in `world.observation.v1` (ADR-047).
pub const MAX_SENSOR_VALUE_BYTES: usize = 512;
/// Minimum sensor quantization in millimetres (ADR-047 section3, ADR-026 privacy floor).
pub const SENSOR_MIN_RESOLUTION_MM: u16 = 100;
/// The only valid `coord_convention` value in v1 (right-handed Y-up metres).
pub const COORD_CONVENTION_RIGHT_HANDED_Y_UP: u8 = 0;
/// The only valid `action_scope` value in v1 (`single_body`; `joint` is deferred).
pub const ACTION_SCOPE_SINGLE_BODY: u8 = 0;

const ACTION_KIND_IMPULSE: &str = "impulse";
const ACTION_KIND_TARGET_VELOCITY: &str = "target_velocity";

/// The set of allowed actuator action kinds in v1 (ADR-047 section1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionKindV1 {
    Impulse,
    TargetVelocity,
}

impl ActionKindV1 {
    const fn as_str(&self) -> &str {
        match self {
            Self::Impulse => ACTION_KIND_IMPULSE,
            Self::TargetVelocity => ACTION_KIND_TARGET_VELOCITY,
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            ACTION_KIND_IMPULSE => Some(Self::Impulse),
            ACTION_KIND_TARGET_VELOCITY => Some(Self::TargetVelocity),
            _ => None,
        }
    }
}

/// Sensor kinds emitted in `world.observation.v1` (ADR-047 section 4, first slice).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorKindV1 {
    Proximity = 0,
    ContactCount = 1,
}

impl SensorKindV1 {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Errors returned by world CBOR codec encode/decode operations.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WorldCodecError {
    #[error("wrong magic bytes")]
    WrongMagic,
    #[error("wrong schema version")]
    WrongVersion,
    #[error("wrong CBOR array length")]
    WrongArrayLength,
    #[error("wrong field type")]
    WrongFieldType,
    #[error("non-finite float value")]
    NonFiniteFloat,
    #[error("payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("unknown action kind (not in v1 allow-list)")]
    UnknownActionKind,
    #[error("action_scope must be {ACTION_SCOPE_SINGLE_BODY} (single_body) in v1")]
    InvalidActionScope,
    #[error("coord_convention must be {COORD_CONVENTION_RIGHT_HANDED_Y_UP} (right_handed_y_up_metres) in v1")]
    InvalidCoordConvention,
    #[error("sensor_min_resolution_mm must be >= {SENSOR_MIN_RESOLUTION_MM}")]
    SensorResolutionBelowMinimum,
    #[error("params_cbor must be a canonical normalized two-float actuator pair")]
    NonCanonicalParamsCbor,
    #[error("World record is not canonical CBOR")]
    NonCanonicalRecord,
    #[error("trailing bytes after CBOR item")]
    TrailingBytes,
    #[error("CBOR decode error")]
    CborError,
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

fn cbor_magic(magic: [u8; 4]) -> ciborium::Value {
    ciborium::Value::Bytes(magic.to_vec())
}

fn cbor_u8(v: u8) -> ciborium::Value {
    ciborium::Value::Integer(ciborium::value::Integer::from(v))
}

fn cbor_u16(v: u16) -> ciborium::Value {
    ciborium::Value::Integer(ciborium::value::Integer::from(v))
}

fn cbor_u32(v: u32) -> ciborium::Value {
    ciborium::Value::Integer(ciborium::value::Integer::from(v))
}

fn cbor_u64(v: u64) -> ciborium::Value {
    ciborium::Value::Integer(ciborium::value::Integer::from(v))
}

fn cbor_id(id: EntityId) -> ciborium::Value {
    let n: u128 = id.inner().into();
    ciborium::Value::Bytes(n.to_be_bytes().to_vec())
}

fn cbor_bytes(b: &[u8]) -> ciborium::Value {
    ciborium::Value::Bytes(b.to_vec())
}

fn decode_magic(val: &ciborium::Value, expected: [u8; 4]) -> Result<(), WorldCodecError> {
    match val {
        ciborium::Value::Bytes(b) if b.as_slice() == expected => Ok(()),
        _ => Err(WorldCodecError::WrongMagic),
    }
}

fn decode_version(val: &ciborium::Value) -> Result<(), WorldCodecError> {
    match val {
        ciborium::Value::Integer(n) if u8::try_from(*n).ok() == Some(VERSION_V1) => Ok(()),
        _ => Err(WorldCodecError::WrongVersion),
    }
}

fn decode_u8(val: &ciborium::Value) -> Result<u8, WorldCodecError> {
    match val {
        ciborium::Value::Integer(n) => {
            u8::try_from(*n).map_err(|_| WorldCodecError::WrongFieldType)
        }
        _ => Err(WorldCodecError::WrongFieldType),
    }
}

fn decode_u32(val: &ciborium::Value) -> Result<u32, WorldCodecError> {
    match val {
        ciborium::Value::Integer(n) => {
            u32::try_from(*n).map_err(|_| WorldCodecError::WrongFieldType)
        }
        _ => Err(WorldCodecError::WrongFieldType),
    }
}

fn decode_u64(val: &ciborium::Value) -> Result<u64, WorldCodecError> {
    match val {
        ciborium::Value::Integer(n) => {
            u64::try_from(*n).map_err(|_| WorldCodecError::WrongFieldType)
        }
        _ => Err(WorldCodecError::WrongFieldType),
    }
}

fn decode_id(val: &ciborium::Value) -> Result<EntityId, WorldCodecError> {
    match val {
        ciborium::Value::Bytes(b) if b.len() == 16 => {
            let mut arr = [0_u8; 16];
            arr.copy_from_slice(b);
            let n = u128::from_be_bytes(arr);
            Ok(EntityId::from_ulid(ulid::Ulid::from(n)))
        }
        _ => Err(WorldCodecError::WrongFieldType),
    }
}

fn decode_bytes_fixed<const N: usize>(val: &ciborium::Value) -> Result<[u8; N], WorldCodecError> {
    match val {
        ciborium::Value::Bytes(b) if b.len() == N => b
            .as_slice()
            .try_into()
            .map_err(|_| WorldCodecError::WrongFieldType),
        _ => Err(WorldCodecError::WrongFieldType),
    }
}

fn decode_bytes_max(val: &ciborium::Value, max: usize) -> Result<Vec<u8>, WorldCodecError> {
    match val {
        ciborium::Value::Bytes(b) => {
            if b.len() > max {
                Err(WorldCodecError::PayloadTooLarge { size: b.len(), max })
            } else {
                Ok(b.clone())
            }
        }
        _ => Err(WorldCodecError::WrongFieldType),
    }
}

fn decode_u16(val: &ciborium::Value) -> Result<u16, WorldCodecError> {
    match val {
        ciborium::Value::Integer(n) => {
            u16::try_from(*n).map_err(|_| WorldCodecError::WrongFieldType)
        }
        _ => Err(WorldCodecError::WrongFieldType),
    }
}

fn cbor_encode(value: &ciborium::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    assert!(ciborium::into_writer(value, &mut buf).is_ok());
    buf
}

fn decode_canonical_record(bytes: &[u8]) -> Result<ciborium::Value, WorldCodecError> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: ciborium::Value =
        ciborium::from_reader(&mut cursor).map_err(|_| WorldCodecError::CborError)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(WorldCodecError::TrailingBytes);
    }
    if cbor_encode(&value).as_slice() != bytes {
        return Err(WorldCodecError::NonCanonicalRecord);
    }
    Ok(value)
}

fn cbor_decode_array(
    bytes: &[u8],
    expected_len: usize,
) -> Result<Vec<ciborium::Value>, WorldCodecError> {
    let value = decode_canonical_record(bytes)?;
    match value {
        ciborium::Value::Array(items) if items.len() == expected_len => Ok(items),
        ciborium::Value::Array(_) => Err(WorldCodecError::WrongArrayLength),
        _ => Err(WorldCodecError::CborError),
    }
}

/// Normalize an actuator's horizontal X/Z pair to finite f32 components and
/// encode the shortest canonical CBOR float representation for each component.
///
/// # Errors
/// Returns [`WorldCodecError::NonFiniteFloat`] if either source value or its
/// f32 conversion is non-finite.
pub fn encode_actuator_pair_v1(x: f64, z: f64) -> Result<Vec<u8>, WorldCodecError> {
    if !x.is_finite() || !z.is_finite() {
        return Err(WorldCodecError::NonFiniteFloat);
    }
    let normalized = [
        x.to_f32().unwrap_or(f32::NAN),
        z.to_f32().unwrap_or(f32::NAN),
    ];
    if !normalized.iter().all(|component| component.is_finite()) {
        return Err(WorldCodecError::NonFiniteFloat);
    }
    Ok(cbor_encode(&ciborium::Value::Array(
        normalized
            .into_iter()
            .map(|component| ciborium::Value::Float(f64::from(component)))
            .collect(),
    )))
}

fn decode_actuator_pair_v1(bytes: &[u8]) -> Result<(f32, f32), WorldCodecError> {
    cbor_decode_array(bytes, 2)
        .map_err(|_| WorldCodecError::NonCanonicalParamsCbor)
        .and_then(|items| {
            items
                .iter()
                .map(|item| {
                    let ciborium::Value::Float(value) = item else {
                        return Err(WorldCodecError::NonCanonicalParamsCbor);
                    };
                    if !value.is_finite() {
                        return Err(WorldCodecError::NonCanonicalParamsCbor);
                    }
                    let normalized = value.to_f32().unwrap_or(f32::NAN);
                    if !normalized.is_finite() || f64::from(normalized).to_bits() != value.to_bits()
                    {
                        return Err(WorldCodecError::NonCanonicalParamsCbor);
                    }
                    Ok(normalized)
                })
                .collect::<Result<Vec<_>, _>>()
                .map(|components| (components[0], components[1]))
        })
}

fn validate_actuator_pair_v1(bytes: &[u8]) -> Result<(), WorldCodecError> {
    decode_actuator_pair_v1(bytes).map(|_| ())
}

fn decode_canonical_action_params_field(
    value: &ciborium::Value,
) -> Result<(Vec<u8>, (f32, f32)), WorldCodecError> {
    let params = decode_bytes_max(value, MAX_ACTION_BYTES)?;
    decode_actuator_pair_v1(&params).map(|velocity| (params, velocity))
}

// ---------------------------------------------------------------------------
// Additional CBOR helpers for f32 and tstr
// ---------------------------------------------------------------------------

fn cbor_f32(v: f32) -> Result<ciborium::Value, WorldCodecError> {
    if !v.is_finite() {
        return Err(WorldCodecError::NonFiniteFloat);
    }
    Ok(ciborium::Value::Float(f64::from(v)))
}

const fn decode_finite_f32(val: &ciborium::Value) -> Result<f32, WorldCodecError> {
    match val {
        ciborium::Value::Float(f) => {
            #[allow(clippy::cast_possible_truncation)]
            let v = *f as f32;
            if v.is_finite() {
                Ok(v)
            } else {
                Err(WorldCodecError::NonFiniteFloat)
            }
        }
        _ => Err(WorldCodecError::WrongFieldType),
    }
}

fn cbor_tstr(s: &str) -> ciborium::Value {
    ciborium::Value::Text(s.to_owned())
}

fn decode_tstr(val: &ciborium::Value) -> Result<String, WorldCodecError> {
    match val {
        ciborium::Value::Text(s) => Ok(s.clone()),
        _ => Err(WorldCodecError::WrongFieldType),
    }
}

// ---------------------------------------------------------------------------
// WorldActionV1 — CBOR definite array, magic WAC1 (ADR-047)
// ---------------------------------------------------------------------------

/// A versioned world action command (ADR-047, `world.action.v1`).
///
/// Array (9 elements):
/// `[magic_bstr4, version_u8=1, actor_id_bstr16, body_id_bstr16,
///   action_kind_tstr, params_cbor_bstr, action_scope_u8, catalogue_version_u32, tick_u64]`
///
/// Max total encoded size: 4,096 bytes. `action_scope` must be `ACTION_SCOPE_SINGLE_BODY` in v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldActionV1 {
    pub actor_entity_id: EntityId,
    pub body_entity_id: EntityId,
    pub action_kind: ActionKindV1,
    /// Canonical CBOR array of exactly two normalized finite f32 floats (X, Z).
    pub params_cbor: Vec<u8>,
    /// Must be `ACTION_SCOPE_SINGLE_BODY` (0) in v1.
    pub action_scope: u8,
    pub catalogue_version: u32,
    pub tick: u64,
}

impl WorldActionV1 {
    /// Encode to canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns [`WorldCodecError::InvalidActionScope`] if `action_scope != ACTION_SCOPE_SINGLE_BODY`.
    /// Returns [`WorldCodecError::NonCanonicalParamsCbor`] unless `params_cbor`
    /// is an exact normalized X/Z actuator pair.
    pub fn encode(&self) -> Result<CanonicalBytes, WorldCodecError> {
        if self.action_scope != ACTION_SCOPE_SINGLE_BODY {
            return Err(WorldCodecError::InvalidActionScope);
        }
        validate_actuator_pair_v1(&self.params_cbor)?;
        let arr = ciborium::Value::Array(vec![
            cbor_magic(*MAGIC_WAC1),
            cbor_u8(VERSION_V1),
            cbor_id(self.actor_entity_id),
            cbor_id(self.body_entity_id),
            cbor_tstr(self.action_kind.as_str()),
            cbor_bytes(&self.params_cbor),
            cbor_u8(self.action_scope),
            cbor_u32(self.catalogue_version),
            cbor_u64(self.tick),
        ]);
        Ok(CanonicalBytes::from_vec(cbor_encode(&arr)))
    }

    /// Decode from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns a [`WorldCodecError`] on any malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, WorldCodecError> {
        Self::decode_with_params(bytes).map(|(action, _)| action)
    }

    fn decode_with_params(bytes: &CanonicalBytes) -> Result<(Self, (f32, f32)), WorldCodecError> {
        if bytes.len() > MAX_ACTION_BYTES {
            return Err(WorldCodecError::PayloadTooLarge {
                size: bytes.len(),
                max: MAX_ACTION_BYTES,
            });
        }
        let items = cbor_decode_array(bytes.as_slice(), 9)?;
        decode_magic(&items[0], *MAGIC_WAC1)?;
        decode_version(&items[1])?;
        let actor_entity_id = decode_id(&items[2])?;
        let body_entity_id = decode_id(&items[3])?;
        let kind_str = decode_tstr(&items[4])?;
        let action_kind =
            ActionKindV1::from_str(&kind_str).ok_or(WorldCodecError::UnknownActionKind)?;
        let (params_cbor, velocity) = decode_canonical_action_params_field(&items[5])?;
        let action_scope = decode_u8(&items[6])?;
        if action_scope != ACTION_SCOPE_SINGLE_BODY {
            return Err(WorldCodecError::InvalidActionScope);
        }
        let catalogue_version = decode_u32(&items[7])?;
        let tick = decode_u64(&items[8])?;
        Ok((
            Self {
                actor_entity_id,
                body_entity_id,
                action_kind,
                params_cbor,
                action_scope,
                catalogue_version,
                tick,
            },
            velocity,
        ))
    }
}

// ---------------------------------------------------------------------------
// WorldObservationV1 — CBOR definite array, magic WOB1 (ADR-047 v3)
// ---------------------------------------------------------------------------

/// A versioned world body observation (ADR-047 v3, `world.observation.v1`).
///
/// Array (20 elements):
/// `[magic_bstr4, version_u8, body_id_bstr16, tick_u64, step_index_u64,
///   pos_x_f32, pos_y_f32, pos_z_f32,
///   orient_w_f32, orient_x_f32, orient_y_f32, orient_z_f32,
///   vel_lin_x_f32, vel_lin_y_f32, vel_lin_z_f32,
///   vel_ang_x_f32, vel_ang_y_f32, vel_ang_z_f32,
///   sensor_kind_u8, sensor_value_bstr]`
///
/// Coordinate system: right-handed Y-up metres. Orientation: unit quaternion (w, x, y, z).
/// All floats are `f32`; non-finite values cause a session fault (fail-closed).
/// Sensor values are pre-quantized before storage per `sensor_min_resolution_u16` in config.
#[derive(Debug, Clone, PartialEq)]
pub struct WorldObservationV1 {
    pub body_entity_id: EntityId,
    pub tick: u64,
    pub step_index: u64,
    pub pos_x: f32,
    pub pos_y: f32,
    pub pos_z: f32,
    pub orient_w: f32,
    pub orient_x: f32,
    pub orient_y: f32,
    pub orient_z: f32,
    pub vel_lin_x: f32,
    pub vel_lin_y: f32,
    pub vel_lin_z: f32,
    pub vel_ang_x: f32,
    pub vel_ang_y: f32,
    pub vel_ang_z: f32,
    pub sensor_kind: u8,
    pub sensor_value: Vec<u8>,
}

impl WorldObservationV1 {
    /// Encode to canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns [`WorldCodecError::NonFiniteFloat`] if any float is non-finite.
    /// Returns [`WorldCodecError::PayloadTooLarge`] if `sensor_value` exceeds `MAX_SENSOR_VALUE_BYTES`.
    pub fn encode(&self) -> Result<CanonicalBytes, WorldCodecError> {
        if self.sensor_value.len() > MAX_SENSOR_VALUE_BYTES {
            return Err(WorldCodecError::PayloadTooLarge {
                size: self.sensor_value.len(),
                max: MAX_SENSOR_VALUE_BYTES,
            });
        }
        let arr = ciborium::Value::Array(vec![
            cbor_magic(*MAGIC_WOB1),
            cbor_u8(VERSION_V1),
            cbor_id(self.body_entity_id),
            cbor_u64(self.tick),
            cbor_u64(self.step_index),
            cbor_f32(self.pos_x)?,
            cbor_f32(self.pos_y)?,
            cbor_f32(self.pos_z)?,
            cbor_f32(self.orient_w)?,
            cbor_f32(self.orient_x)?,
            cbor_f32(self.orient_y)?,
            cbor_f32(self.orient_z)?,
            cbor_f32(self.vel_lin_x)?,
            cbor_f32(self.vel_lin_y)?,
            cbor_f32(self.vel_lin_z)?,
            cbor_f32(self.vel_ang_x)?,
            cbor_f32(self.vel_ang_y)?,
            cbor_f32(self.vel_ang_z)?,
            cbor_u8(self.sensor_kind),
            cbor_bytes(&self.sensor_value),
        ]);
        Ok(CanonicalBytes::from_vec(cbor_encode(&arr)))
    }

    /// Decode from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns a [`WorldCodecError`] on any malformed or non-finite input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, WorldCodecError> {
        let items = cbor_decode_array(bytes.as_slice(), 20)?;
        decode_magic(&items[0], *MAGIC_WOB1)?;
        decode_version(&items[1])?;
        let body_entity_id = decode_id(&items[2])?;
        let tick = decode_u64(&items[3])?;
        let step_index = decode_u64(&items[4])?;
        let pos_x = decode_finite_f32(&items[5])?;
        let pos_y = decode_finite_f32(&items[6])?;
        let pos_z = decode_finite_f32(&items[7])?;
        let orient_w = decode_finite_f32(&items[8])?;
        let orient_x = decode_finite_f32(&items[9])?;
        let orient_y = decode_finite_f32(&items[10])?;
        let orient_z = decode_finite_f32(&items[11])?;
        let vel_lin_x = decode_finite_f32(&items[12])?;
        let vel_lin_y = decode_finite_f32(&items[13])?;
        let vel_lin_z = decode_finite_f32(&items[14])?;
        let vel_ang_x = decode_finite_f32(&items[15])?;
        let vel_ang_y = decode_finite_f32(&items[16])?;
        let vel_ang_z = decode_finite_f32(&items[17])?;
        let sensor_kind = decode_u8(&items[18])?;
        let sensor_value = decode_bytes_max(&items[19], MAX_SENSOR_VALUE_BYTES)?;
        Ok(Self {
            body_entity_id,
            tick,
            step_index,
            pos_x,
            pos_y,
            pos_z,
            orient_w,
            orient_x,
            orient_y,
            orient_z,
            vel_lin_x,
            vel_lin_y,
            vel_lin_z,
            vel_ang_x,
            vel_ang_y,
            vel_ang_z,
            sensor_kind,
            sensor_value,
        })
    }
}

// ---------------------------------------------------------------------------
// WorldConfigV1 — CBOR definite array, magic WCF1 (ADR-047 v3)
// ---------------------------------------------------------------------------

/// Pinned world configuration (ADR-047 v3, `world.config.v1`).
///
/// Array (14 elements):
/// `[magic_bstr4, version_u8=1, timestep_u32_micros, coord_convention_u8,
///   gravity_x_f32, gravity_y_f32, gravity_z_f32,
///   backend_id_tstr, backend_version_tstr, backend_content_hash_bstr32,
///   action_schema_version_u32, observation_schema_version_u32,
///   sensor_min_resolution_u16, actuator_catalogue_version_u32]`
///
/// `coord_convention_u8`: `0 = right_handed_y_up_metres` (only valid value in v1).
/// `sensor_min_resolution_u16`: minimum quantization in millimetres (minimum 100mm).
#[derive(Debug, Clone, PartialEq)]
pub struct WorldConfigV1 {
    /// Fixed simulation timestep in microseconds.
    pub timestep_micros: u32,
    /// `0 = right_handed_y_up_metres` (only valid in v1).
    pub coord_convention: u8,
    pub gravity_x: f32,
    pub gravity_y: f32,
    pub gravity_z: f32,
    pub backend_id: String,
    pub backend_version: String,
    pub backend_content_hash: [u8; 32],
    pub action_schema_version: u32,
    pub observation_schema_version: u32,
    /// Minimum sensor quantization in millimetres (must be ≥ 100).
    pub sensor_min_resolution_mm: u16,
    pub actuator_catalogue_version: u32,
}

impl WorldConfigV1 {
    /// Encode to canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns [`WorldCodecError::NonFiniteFloat`] if any gravity component is non-finite.
    pub fn encode(&self) -> Result<CanonicalBytes, WorldCodecError> {
        if self.coord_convention != COORD_CONVENTION_RIGHT_HANDED_Y_UP {
            return Err(WorldCodecError::InvalidCoordConvention);
        }
        if self.sensor_min_resolution_mm < SENSOR_MIN_RESOLUTION_MM {
            return Err(WorldCodecError::SensorResolutionBelowMinimum);
        }
        let arr = ciborium::Value::Array(vec![
            cbor_magic(*MAGIC_WCF1),
            cbor_u8(VERSION_V1),
            cbor_u32(self.timestep_micros),
            cbor_u8(self.coord_convention),
            cbor_f32(self.gravity_x)?,
            cbor_f32(self.gravity_y)?,
            cbor_f32(self.gravity_z)?,
            cbor_tstr(&self.backend_id),
            cbor_tstr(&self.backend_version),
            cbor_bytes(&self.backend_content_hash),
            cbor_u32(self.action_schema_version),
            cbor_u32(self.observation_schema_version),
            cbor_u16(self.sensor_min_resolution_mm),
            cbor_u32(self.actuator_catalogue_version),
        ]);
        Ok(CanonicalBytes::from_vec(cbor_encode(&arr)))
    }

    /// Decode from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns a [`WorldCodecError`] on any malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, WorldCodecError> {
        let items = cbor_decode_array(bytes.as_slice(), 14)?;
        decode_magic(&items[0], *MAGIC_WCF1)?;
        decode_version(&items[1])?;
        let timestep_micros = decode_u32(&items[2])?;
        let coord_convention = decode_u8(&items[3])?;
        if coord_convention != COORD_CONVENTION_RIGHT_HANDED_Y_UP {
            return Err(WorldCodecError::InvalidCoordConvention);
        }
        let gravity_x = decode_finite_f32(&items[4])?;
        let gravity_y = decode_finite_f32(&items[5])?;
        let gravity_z = decode_finite_f32(&items[6])?;
        let backend_id = decode_tstr(&items[7])?;
        let backend_version = decode_tstr(&items[8])?;
        let backend_content_hash = decode_bytes_fixed::<32>(&items[9])?;
        let action_schema_version = decode_u32(&items[10])?;
        let observation_schema_version = decode_u32(&items[11])?;
        let sensor_min_resolution_mm = decode_u16(&items[12])?;
        if sensor_min_resolution_mm < SENSOR_MIN_RESOLUTION_MM {
            return Err(WorldCodecError::SensorResolutionBelowMinimum);
        }
        let actuator_catalogue_version = decode_u32(&items[13])?;
        Ok(Self {
            timestep_micros,
            coord_convention,
            gravity_x,
            gravity_y,
            gravity_z,
            backend_id,
            backend_version,
            backend_content_hash,
            action_schema_version,
            observation_schema_version,
            sensor_min_resolution_mm,
            actuator_catalogue_version,
        })
    }
}

// ---------------------------------------------------------------------------
// Action folding helpers
// ---------------------------------------------------------------------------

fn decode_horizontal_velocity_params(params: &[u8]) -> Option<(f32, f32)> {
    decode_actuator_pair_v1(params).ok()
}

// ---------------------------------------------------------------------------
// World backend trait (physics seam)
// ---------------------------------------------------------------------------

/// A swappable physics backend; the built-in adapter uses simple kinematics.
pub trait WorldBackend: Send + Sync {
    /// Human-readable name for this backend.
    fn name(&self) -> &'static str;

    /// Simulate one pinned-duration step and return body observations.
    fn step(&self, bodies: &[Body], timestep_micros: u32) -> Vec<WorldObservation>;
}

/// A body in the world.
#[derive(Debug, Clone, PartialEq)]
pub struct Body {
    pub entity_id: EntityId,
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub vx: f64,
    pub vy: f64,
    pub vz: f64,
}

/// An observation of a body's position and linear velocity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorldObservation {
    pub entity_id: EntityId,
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub vx: f64,
    pub vy: f64,
    pub vz: f64,
}

/// A world body represented by a core-owned named ENU coordinate.
#[derive(Clone, Copy, PartialEq)]
pub struct WorldCoordinateBody {
    entity_id: EntityId,
    position: WorldCoordinateV1,
    east_velocity_metres_per_step: f64,
    north_velocity_metres_per_step: f64,
    up_velocity_metres_per_step: f64,
}

impl WorldCoordinateBody {
    /// Construct a body with one-step East/North/Up velocity components.
    #[must_use]
    pub const fn new(
        entity_id: EntityId,
        position: WorldCoordinateV1,
        east_velocity_metres_per_step: f64,
        north_velocity_metres_per_step: f64,
        up_velocity_metres_per_step: f64,
    ) -> Self {
        Self {
            entity_id,
            position,
            east_velocity_metres_per_step,
            north_velocity_metres_per_step,
            up_velocity_metres_per_step,
        }
    }

    /// Return the entity identifier.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.entity_id
    }

    /// Return the current named world coordinate.
    #[must_use]
    pub const fn position(self) -> WorldCoordinateV1 {
        self.position
    }
}

/// A world-body observation represented by a named ENU coordinate.
#[derive(Clone, Copy, PartialEq)]
pub struct WorldCoordinateObservation {
    entity_id: EntityId,
    position: WorldCoordinateV1,
}

impl WorldCoordinateObservation {
    /// Return the observed entity identifier.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.entity_id
    }

    /// Return the observed named world coordinate.
    #[must_use]
    pub const fn position(self) -> WorldCoordinateV1 {
        self.position
    }
}

// ---------------------------------------------------------------------------
// Built-in backend: SimpleKinematicBackend
// ---------------------------------------------------------------------------

/// Simple Euler integration of three-dimensional velocity over the pinned step.
#[derive(Default)]
pub struct SimpleKinematicBackend;

impl SimpleKinematicBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Advance named ENU bodies by one step.
    ///
    /// # Errors
    ///
    /// Returns [`WorldTransformError::NonFiniteCoordinate`] when a velocity
    /// component or translated coordinate is not finite.
    pub fn step_coordinates(
        &self,
        bodies: &[WorldCoordinateBody],
    ) -> Result<Vec<WorldCoordinateObservation>, WorldTransformError> {
        bodies
            .iter()
            .map(|body| {
                let position = body.position.translated_by(
                    body.east_velocity_metres_per_step,
                    body.north_velocity_metres_per_step,
                    body.up_velocity_metres_per_step,
                )?;
                Ok(WorldCoordinateObservation {
                    entity_id: body.entity_id,
                    position,
                })
            })
            .collect()
    }
}

impl WorldBackend for SimpleKinematicBackend {
    fn name(&self) -> &'static str {
        "simple-kinematic"
    }

    fn step(&self, bodies: &[Body], timestep_micros: u32) -> Vec<WorldObservation> {
        let seconds = f64::from(timestep_micros) / 1_000_000.0;
        bodies
            .iter()
            .map(|body| WorldObservation {
                entity_id: body.entity_id,
                x: body.vx.mul_add(seconds, body.x),
                y: body.vy.mul_add(seconds, body.y),
                z: body.vz.mul_add(seconds, body.z),
                vx: body.vx,
                vy: body.vy,
                vz: body.vz,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Plugin descriptor
// ---------------------------------------------------------------------------

/// World simulation plugin.
#[derive(Clone)]
pub struct WorldPlugin {
    id: PluginId,
    allowed_action_kinds: Vec<String>,
    catalogue_version: u32,
    known_bodies: HashSet<EntityId>,
}

impl Default for WorldPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl WorldPlugin {
    /// Create a new world plugin with default actuator allow-list (`["impulse", "target_velocity"]`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: PluginId::new(),
            allowed_action_kinds: vec!["impulse".to_owned(), "target_velocity".to_owned()],
            catalogue_version: 1,
            known_bodies: HashSet::new(),
        }
    }

    /// Pinned catalogue version.
    #[must_use]
    pub const fn catalogue_version(&self) -> u32 {
        self.catalogue_version
    }

    /// Configure allowed action kinds.
    #[must_use]
    pub fn with_allowed_actions(mut self, actions: impl IntoIterator<Item = String>) -> Self {
        self.allowed_action_kinds = actions.into_iter().collect();
        self
    }

    /// Configure known body entities.
    #[must_use]
    pub fn with_bodies(mut self, bodies: impl IntoIterator<Item = EntityId>) -> Self {
        self.known_bodies = bodies.into_iter().collect();
        self
    }

    /// Configure pinned catalogue version.
    #[must_use]
    pub const fn with_catalogue_version(mut self, version: u32) -> Self {
        self.catalogue_version = version;
        self
    }

    /// Add a known body entity ID.
    pub fn add_body(&mut self, body: EntityId) {
        self.known_bodies.insert(body);
    }
}

impl Plugin for WorldPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "world"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![
                Kind::new(EVENT_TYPE_ACTION_V1),
                Kind::new(EVENT_TYPE_OBSERVATION_V1),
                Kind::new(EVENT_TYPE_CONFIG_V1),
            ],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: true,
            has_reducer: true,
        }
    }
}

impl ActionApprover for WorldPlugin {
    fn approve(
        &self,
        proposal: &ProposedAction,
    ) -> Result<pos_core::event::EventDraft, ActionRejected> {
        if proposal.event_type.as_str() != EVENT_TYPE_ACTION_V1 {
            return Err(ActionRejected::UnknownEventType);
        }
        if proposal.capability.as_str() != "world.action.v1.submit" {
            return Err(ActionRejected::CapabilityNotGranted);
        }
        if proposal.payload.len() > MAX_PROPOSED_ACTION_PAYLOAD_BYTES {
            return Err(ActionRejected::PayloadTooLarge {
                size: proposal.payload.len(),
                max: MAX_PROPOSED_ACTION_PAYLOAD_BYTES,
            });
        }

        let action = WorldActionV1::decode(&proposal.payload)
            .map_err(|error| ActionRejected::DomainValidationFailed(error.to_string()))?;

        if action.actor_entity_id != proposal.actor_entity_id {
            return Err(ActionRejected::InvalidActorEntityId);
        }

        if action.catalogue_version != self.catalogue_version {
            return Err(ActionRejected::DomainValidationFailed(
                "catalogue version mismatch".to_owned(),
            ));
        }

        if !self
            .allowed_action_kinds
            .iter()
            .any(|kind| kind == action.action_kind.as_str())
        {
            return Err(ActionRejected::DomainValidationFailed(
                "action kind is not in the allow-list".to_owned(),
            ));
        }

        if !self.known_bodies.contains(&action.body_entity_id) {
            return Err(ActionRejected::DomainValidationFailed(
                "unknown body entity ID".to_owned(),
            ));
        }

        Ok(pos_core::event::EventDraft::new(
            proposal.actor_entity_id,
            proposal.event_type.clone(),
            proposal.payload.clone(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Produces `world.config.v1` once on the first tick and `world.observation.v1` per body per step.
pub struct WorldDriver {
    initial_entities: Vec<Body>,
    entities: Vec<Body>,
    backend: Box<dyn WorldBackend>,
    tick: u64,
    /// Counts simulation steps independently of timeline ticks (same value in V1).
    step_index: u64,
    config: WorldConfigV1,
    config_emitted: bool,
    applied_action_seqs: Vec<u64>,
    causation_by_body: Vec<(EntityId, EventId)>,
    config_entity: EntityId,
    staged_step: Option<WorldDriverState>,
    staged_restore: Option<WorldDriverState>,
}

#[derive(Clone)]
struct WorldDriverState {
    entities: Vec<Body>,
    tick: u64,
    step_index: u64,
    config_emitted: bool,
    applied_action_seqs: Vec<u64>,
    causation_by_body: Vec<(EntityId, EventId)>,
}

impl WorldDriver {
    /// Create a new world driver with the given backend and session config.
    #[must_use]
    pub fn new(
        mut entities: Vec<Body>,
        backend: Box<dyn WorldBackend>,
        config: WorldConfigV1,
    ) -> Self {
        entities.sort_unstable_by_key(|body| body.entity_id);
        Self {
            initial_entities: entities.clone(),
            entities,
            backend,
            tick: 0,
            step_index: 0,
            config,
            config_emitted: false,
            applied_action_seqs: Vec::new(),
            causation_by_body: Vec::new(),
            config_entity: EntityId::new(),
            staged_step: None,
            staged_restore: None,
        }
    }

    /// Pin the session-global configuration entity for reproducible evidence.
    #[must_use]
    pub const fn with_config_entity(mut self, entity: EntityId) -> Self {
        self.config_entity = entity;
        self
    }

    fn state(&self) -> WorldDriverState {
        WorldDriverState {
            entities: self.entities.clone(),
            tick: self.tick,
            step_index: self.step_index,
            config_emitted: self.config_emitted,
            applied_action_seqs: self.applied_action_seqs.clone(),
            causation_by_body: self.causation_by_body.clone(),
        }
    }

    fn restore_state(&mut self, state: WorldDriverState) {
        self.entities = state.entities;
        self.tick = state.tick;
        self.step_index = state.step_index;
        self.config_emitted = state.config_emitted;
        self.applied_action_seqs = state.applied_action_seqs;
        self.causation_by_body = state.causation_by_body;
    }

    fn apply_action_to_entities(
        entities: &mut [Body],
        action: &WorldActionV1,
        (vx, vz): (f32, f32),
    ) -> bool {
        let Some(body) = entities
            .iter_mut()
            .find(|body| body.entity_id == action.body_entity_id)
        else {
            return false;
        };
        match action.action_kind {
            ActionKindV1::Impulse => {
                body.vx += f64::from(vx);
                body.vz += f64::from(vz);
            }
            ActionKindV1::TargetVelocity => {
                body.vx = f64::from(vx);
                body.vz = f64::from(vz);
            }
        }
        true
    }

    /// Quantize a raw sensor value to the session's minimum resolution.
    ///
    /// Values are rounded to the nearest multiple of `sensor_min_resolution_mm` millimetres.
    fn quantize_sensor(raw: f32, resolution_mm: u16) -> f32 {
        let r = f32::from(resolution_mm) / 1_000.0; // mm → metres
        (raw / r).round() * r
    }

    fn checked_f32(value: f64, axis: &'static str) -> Result<f32, RuntimeError> {
        if !value.is_finite() {
            return Err(RuntimeError::InvalidPayload {
                event_type: EVENT_TYPE_OBSERVATION_V1.to_owned(),
                reason: format!("backend produced a non-finite float value for {axis}"),
            });
        }
        let converted = value.to_f32().unwrap_or(f32::NAN);
        if converted.is_finite() {
            return Ok(converted);
        }
        Err(RuntimeError::InvalidPayload {
            event_type: EVENT_TYPE_OBSERVATION_V1.to_owned(),
            reason: format!("backend produced a non-representable {axis} coordinate"),
        })
    }

    fn config_draft(&mut self) -> Result<Option<pos_core::event::EventDraft>, RuntimeError> {
        if self.config_emitted {
            return Ok(None);
        }
        let payload = self
            .config
            .encode()
            .map_err(|error| RuntimeError::InvalidPayload {
                event_type: EVENT_TYPE_CONFIG_V1.to_owned(),
                reason: error.to_string(),
            })?;
        self.config_emitted = true;
        Ok(Some(pos_core::event::EventDraft::new(
            self.config_entity,
            Kind::new(EVENT_TYPE_CONFIG_V1),
            payload,
        )))
    }

    fn apply_observed_actions(&mut self, events: &[Event]) -> Result<(), RuntimeError> {
        for event in events {
            if event.event_type.as_str() != EVENT_TYPE_ACTION_V1
                || self.applied_action_seqs.contains(&event.seq.as_u64())
            {
                continue;
            }
            let (action, velocity) =
                WorldActionV1::decode_with_params(&event.payload).map_err(|error| {
                    RuntimeError::InvalidPayload {
                        event_type: EVENT_TYPE_ACTION_V1.to_owned(),
                        reason: error.to_string(),
                    }
                })?;
            if action.catalogue_version != self.config.actuator_catalogue_version {
                return Err(RuntimeError::InvalidPayload {
                    event_type: EVENT_TYPE_ACTION_V1.to_owned(),
                    reason: "action catalogue version differs from pinned world configuration"
                        .to_owned(),
                });
            }
            if !Self::apply_action_to_entities(&mut self.entities, &action, velocity) {
                return Err(RuntimeError::InvalidPayload {
                    event_type: EVENT_TYPE_ACTION_V1.to_owned(),
                    reason: "action target is not a staged world body".to_owned(),
                });
            }
            self.applied_action_seqs.push(event.seq.as_u64());
            if let Some((_, causation)) = self
                .causation_by_body
                .iter_mut()
                .find(|(body, _)| *body == action.body_entity_id)
            {
                *causation = event.id;
            } else {
                self.causation_by_body
                    .push((action.body_entity_id, event.id));
            }
        }
        Ok(())
    }

    fn emit_observations(
        &self,
        observations: &[WorldObservation],
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        observations
            .iter()
            .map(|observation| {
                [
                    ("x", observation.x),
                    ("y", observation.y),
                    ("z", observation.z),
                    ("vx", observation.vx),
                    ("vy", observation.vy),
                    ("vz", observation.vz),
                ]
                .into_iter()
                .enumerate()
                .try_fold([0.0_f32; 6], |mut components, (index, (axis, value))| {
                    Self::checked_f32(value, axis).map(|converted| {
                        components[index] = converted;
                        components
                    })
                })
                .and_then(|[x, y, z, vx, vy, vz]| {
                    WorldObservationV1 {
                        body_entity_id: observation.entity_id,
                        tick: self.tick,
                        step_index: self.step_index,
                        pos_x: Self::quantize_sensor(x, self.config.sensor_min_resolution_mm),
                        pos_y: Self::quantize_sensor(y, self.config.sensor_min_resolution_mm),
                        pos_z: Self::quantize_sensor(z, self.config.sensor_min_resolution_mm),
                        orient_w: 1.0,
                        orient_x: 0.0,
                        orient_y: 0.0,
                        orient_z: 0.0,
                        vel_lin_x: vx,
                        vel_lin_y: vy,
                        vel_lin_z: vz,
                        vel_ang_x: 0.0,
                        vel_ang_y: 0.0,
                        vel_ang_z: 0.0,
                        sensor_kind: SensorKindV1::Proximity.as_u8(),
                        sensor_value: vec![],
                    }
                    .encode()
                    .map_err(|error| RuntimeError::InvalidPayload {
                        event_type: EVENT_TYPE_OBSERVATION_V1.to_owned(),
                        reason: error.to_string(),
                    })
                    .map(|payload| {
                        let mut draft = pos_core::event::EventDraft::new(
                            observation.entity_id,
                            Kind::new(EVENT_TYPE_OBSERVATION_V1),
                            payload,
                        );
                        draft.causation_id = self
                            .causation_by_body
                            .iter()
                            .rev()
                            .find(|(body, _)| *body == observation.entity_id)
                            .map(|(_, event_id)| *event_id);
                        draft
                    })
                })
            })
            .collect()
    }
}

impl Default for WorldDriver {
    fn default() -> Self {
        Self::new(
            vec![],
            Box::new(SimpleKinematicBackend::new()),
            WorldConfigV1 {
                timestep_micros: 16_667,
                coord_convention: COORD_CONVENTION_RIGHT_HANDED_Y_UP,
                gravity_x: 0.0,
                gravity_y: -9.81,
                gravity_z: 0.0,
                backend_id: "simple-kinematic".to_owned(),
                backend_version: "1.0.0".to_owned(),
                backend_content_hash: [0u8; 32],
                action_schema_version: 1,
                observation_schema_version: 1,
                sensor_min_resolution_mm: SENSOR_MIN_RESOLUTION_MM,
                actuator_catalogue_version: 1,
            },
        )
    }
}

impl Driver for WorldDriver {
    fn name(&self) -> &'static str {
        "world-driver"
    }

    fn event_subscriptions(&self) -> &[Kind] {
        static SUBSCRIPTIONS: std::sync::OnceLock<Vec<Kind>> = std::sync::OnceLock::new();
        SUBSCRIPTIONS.get_or_init(|| vec![Kind::new(EVENT_TYPE_ACTION_V1)])
    }

    fn needs_recovery_payload(&self, header: &RecoveryEventHeader) -> bool {
        matches!(
            header.event_type().as_str(),
            EVENT_TYPE_ACTION_V1 | EVENT_TYPE_OBSERVATION_V1 | EVENT_TYPE_CONFIG_V1
        )
    }

    fn stage_restore_from_history(
        &mut self,
        evidence: &DriverRecoveryEvidence,
    ) -> Result<(), RuntimeError> {
        let mut restored = WorldDriverState {
            entities: self.initial_entities.clone(),
            tick: 0,
            step_index: 0,
            config_emitted: false,
            applied_action_seqs: Vec::new(),
            causation_by_body: Vec::new(),
        };
        for event in evidence.events() {
            let event_type = event.header().event_type().as_str();
            let Some(payload) = event.payload() else {
                continue;
            };
            if event_type == EVENT_TYPE_ACTION_V1 {
                let (action, velocity) =
                    WorldActionV1::decode_with_params(payload).map_err(|error| {
                        RuntimeError::InvalidPayload {
                            event_type: EVENT_TYPE_ACTION_V1.to_owned(),
                            reason: error.to_string(),
                        }
                    })?;
                if action.catalogue_version != self.config.actuator_catalogue_version {
                    return Err(RuntimeError::InvalidPayload {
                        event_type: EVENT_TYPE_ACTION_V1.to_owned(),
                        reason: "action catalogue version differs from pinned world configuration"
                            .to_owned(),
                    });
                }
                if !Self::apply_action_to_entities(&mut restored.entities, &action, velocity) {
                    return Err(RuntimeError::InvalidPayload {
                        event_type: EVENT_TYPE_ACTION_V1.to_owned(),
                        reason: "action target is not a staged world body".to_owned(),
                    });
                }
                restored
                    .applied_action_seqs
                    .push(event.header().seq().as_u64());
                if let Some((_, causation)) = restored
                    .causation_by_body
                    .iter_mut()
                    .find(|(body, _)| *body == action.body_entity_id)
                {
                    *causation = event.header().id();
                } else {
                    restored
                        .causation_by_body
                        .push((action.body_entity_id, event.header().id()));
                }
                restored.tick = restored.tick.max(action.tick.saturating_add(1));
            } else if event_type == EVENT_TYPE_OBSERVATION_V1 {
                let observation = WorldObservationV1::decode(payload).map_err(|error| {
                    RuntimeError::InvalidPayload {
                        event_type: EVENT_TYPE_OBSERVATION_V1.to_owned(),
                        reason: error.to_string(),
                    }
                })?;
                if let Some(body) = restored
                    .entities
                    .iter_mut()
                    .find(|body| body.entity_id == observation.body_entity_id)
                {
                    body.x = f64::from(observation.pos_x);
                    body.y = f64::from(observation.pos_y);
                    body.z = f64::from(observation.pos_z);
                    body.vx = f64::from(observation.vel_lin_x);
                    body.vy = f64::from(observation.vel_lin_y);
                    body.vz = f64::from(observation.vel_lin_z);
                }
                restored.tick = restored.tick.max(observation.tick.saturating_add(1));
                restored.step_index = restored
                    .step_index
                    .max(observation.step_index.saturating_add(1));
            } else if event_type == EVENT_TYPE_CONFIG_V1 {
                let config = WorldConfigV1::decode(payload).map_err(|error| {
                    RuntimeError::InvalidPayload {
                        event_type: EVENT_TYPE_CONFIG_V1.to_owned(),
                        reason: error.to_string(),
                    }
                })?;
                if config != self.config {
                    return Err(RuntimeError::InvalidPayload {
                        event_type: EVENT_TYPE_CONFIG_V1.to_owned(),
                        reason:
                            "recovered world configuration differs from the pinned configuration"
                                .to_owned(),
                    });
                }
                restored.config_emitted = true;
            }
        }
        self.staged_restore = Some(restored);
        Ok(())
    }

    fn commit_restore_from_history(&mut self) {
        if let Some(restored) = self.staged_restore.take() {
            self.restore_state(restored);
        }
    }

    fn abort_restore_from_history(&mut self) {
        self.staged_restore = None;
    }

    fn commit_step(&mut self) {
        self.staged_step = None;
    }

    fn abort_step(&mut self) {
        if let Some(previous) = self.staged_step.take() {
            self.restore_state(previous);
        }
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        self.staged_step = Some(self.state());
        let result = (|| {
            let mut drafts = Vec::new();
            if let Some(config) = self.config_draft()? {
                drafts.push(config);
            }
            self.apply_observed_actions(observations.events())?;

            if self
                .entities
                .windows(2)
                .any(|pair| pair[0].entity_id == pair[1].entity_id)
            {
                return Err(RuntimeError::InvalidPayload {
                    event_type: EVENT_TYPE_OBSERVATION_V1.to_owned(),
                    reason: "duplicate staged body identifiers".to_owned(),
                });
            }

            let mut step_obs = self
                .backend
                .step(&self.entities, self.config.timestep_micros);
            step_obs.sort_unstable_by_key(|observation| observation.entity_id);
            if step_obs.len() != self.entities.len()
                || step_obs
                    .iter()
                    .zip(&self.entities)
                    .any(|(observation, body)| observation.entity_id != body.entity_id)
            {
                return Err(RuntimeError::InvalidPayload {
                    event_type: EVENT_TYPE_OBSERVATION_V1.to_owned(),
                    reason: "backend observation body set differs from staged bodies".to_owned(),
                });
            }
            for (body, obs) in self.entities.iter_mut().zip(&step_obs) {
                body.x = obs.x;
                body.y = obs.y;
                body.z = obs.z;
                body.vx = obs.vx;
                body.vy = obs.vy;
                body.vz = obs.vz;
            }

            drafts.extend(self.emit_observations(&step_obs)?);
            self.tick = self.tick.wrapping_add(1);
            self.step_index = self.step_index.wrapping_add(1);
            Ok(StepOutput::new(drafts))
        })();
        if result.is_err() {
            self.abort_step();
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

/// Tracks `observation_count` and `body_count` in State.
pub struct WorldReducer;

impl Reducer for WorldReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("observation_count", serde_json::Value::Number(0.into()));
        s.set("body_count", serde_json::Value::Number(0.into()));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1 {
            let Ok(observation) = WorldObservationV1::decode(&event.payload) else {
                return;
            };
            let observation_count = state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set(
                "observation_count",
                serde_json::Value::Number((observation_count + 1).into()),
            );
            state.set("last_x", serde_json::json!(observation.pos_x));
            state.set("last_y", serde_json::json!(observation.pos_y));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected world fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
        }
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful world fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }

    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, SchemaVersion},
        ids::{EntityId, EventId},
        CoreError, ErasureContainmentGateV1,
    };
    use pos_runtime::{PluginRegistry, TimelineHistorySegment};
    use pos_store::{open_store as open_unbound_store, StoreConfig};
    use std::sync::Arc;

    fn open_store(config: StoreConfig) -> Result<Box<dyn pos_core::EventStore>, CoreError> {
        let mut store = open_unbound_store(config)?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        Ok(store)
    }

    fn make_observation_event(entity: EntityId) -> Event {
        let mut observation = sample_observation();
        observation.body_entity_id = entity;

        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_OBSERVATION_V1),
            payload: observation.encode().test_ok(),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    fn make_other_event(entity: EntityId) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("other.event"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    fn make_versioned_event(
        seq: u64,
        entity: EntityId,
        event_type: &str,
        payload: CanonicalBytes,
    ) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(event_type),
            payload,
            wall_time: WallTime::from_micros(seq),
            seq: Seq::from_u64(seq),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        }
    }

    fn overlong_version(bytes: &CanonicalBytes) -> CanonicalBytes {
        let bytes = bytes.as_slice();
        assert_eq!(bytes[6], VERSION_V1);
        let mut noncanonical = bytes[..6].to_vec();
        noncanonical.extend_from_slice(&[0x18, VERSION_V1]);
        noncanonical.extend_from_slice(&bytes[7..]);
        CanonicalBytes::from_vec(noncanonical)
    }

    // ---------------------------------------------------------------------------
    // WorldActionV1 codec tests
    // ---------------------------------------------------------------------------

    fn sample_action() -> WorldActionV1 {
        WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: EntityId::new(),
            action_kind: ActionKindV1::Impulse,
            params_cbor: encode_actuator_pair_v1(0.0, 0.0).test_ok(),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 42,
            tick: 100,
        }
    }

    fn sample_observation() -> WorldObservationV1 {
        WorldObservationV1 {
            body_entity_id: EntityId::new(),
            tick: 7,
            step_index: 3,
            pos_x: 1.0,
            pos_y: 2.0,
            pos_z: 3.0,
            orient_w: 1.0,
            orient_x: 0.0,
            orient_y: 0.0,
            orient_z: 0.0,
            vel_lin_x: 0.1,
            vel_lin_y: 0.2,
            vel_lin_z: 0.0,
            vel_ang_x: 0.0,
            vel_ang_y: 0.0,
            vel_ang_z: 0.0,
            sensor_kind: 0,
            sensor_value: vec![],
        }
    }

    fn sample_config() -> WorldConfigV1 {
        WorldConfigV1 {
            timestep_micros: 1_000_000,
            coord_convention: 0,
            gravity_x: 0.0,
            gravity_y: -9.81,
            gravity_z: 0.0,
            backend_id: "simple-kinematic".to_owned(),
            backend_version: "1.0.0".to_owned(),
            backend_content_hash: [3u8; 32],
            action_schema_version: 1,
            observation_schema_version: 1,
            sensor_min_resolution_mm: 100,
            actuator_catalogue_version: 1,
        }
    }

    fn rewrite_array_field(
        bytes: &CanonicalBytes,
        index: usize,
        replacement: ciborium::Value,
    ) -> CanonicalBytes {
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut value: ciborium::Value = ciborium::from_reader(&mut cursor).test_ok();
        if let ciborium::Value::Array(ref mut items) = value {
            items[index] = replacement;
        }
        CanonicalBytes::from_vec(cbor_encode(&value))
    }

    struct NonFiniteBackend;

    impl WorldBackend for NonFiniteBackend {
        fn name(&self) -> &'static str {
            "non-finite-test-backend"
        }

        fn step(&self, bodies: &[Body], _timestep_micros: u32) -> Vec<WorldObservation> {
            bodies
                .iter()
                .map(|body| WorldObservation {
                    entity_id: body.entity_id,
                    x: f64::NAN,
                    y: body.y,
                    z: body.z,
                    vx: body.vx,
                    vy: body.vy,
                    vz: body.vz,
                })
                .collect()
        }
    }

    struct YNonFiniteBackend;

    impl WorldBackend for YNonFiniteBackend {
        fn name(&self) -> &'static str {
            "y-non-finite-test-backend"
        }

        fn step(&self, bodies: &[Body], _timestep_micros: u32) -> Vec<WorldObservation> {
            bodies
                .iter()
                .map(|body| WorldObservation {
                    entity_id: body.entity_id,
                    x: body.x,
                    y: f64::NAN,
                    z: body.z,
                    vx: body.vx,
                    vy: body.vy,
                    vz: body.vz,
                })
                .collect()
        }
    }

    struct OutOfRangeBackend;

    impl WorldBackend for OutOfRangeBackend {
        fn name(&self) -> &'static str {
            "out-of-range-test-backend"
        }

        fn step(&self, bodies: &[Body], _timestep_micros: u32) -> Vec<WorldObservation> {
            bodies
                .iter()
                .map(|body| WorldObservation {
                    entity_id: body.entity_id,
                    x: f64::MAX,
                    y: body.y,
                    z: body.z,
                    vx: body.vx,
                    vy: body.vy,
                    vz: body.vz,
                })
                .collect()
        }
    }

    #[derive(Clone, Copy)]
    enum InvalidObservationComponent {
        Z,
        Vx,
        Vy,
        Vz,
    }

    struct InvalidObservationComponentBackend {
        component: InvalidObservationComponent,
        first_step_invalid: std::sync::atomic::AtomicBool,
    }

    impl WorldBackend for InvalidObservationComponentBackend {
        fn name(&self) -> &'static str {
            "invalid-observation-component-test-backend"
        }

        fn step(&self, bodies: &[Body], _timestep_micros: u32) -> Vec<WorldObservation> {
            let inject_invalid = self
                .first_step_invalid
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            bodies
                .iter()
                .map(|body| {
                    let mut observed = WorldObservation {
                        entity_id: body.entity_id,
                        x: body.x,
                        y: body.y,
                        z: body.z,
                        vx: body.vx,
                        vy: body.vy,
                        vz: body.vz,
                    };
                    if inject_invalid {
                        match self.component {
                            InvalidObservationComponent::Z => observed.z = f64::MAX,
                            InvalidObservationComponent::Vx => observed.vx = f64::MAX,
                            InvalidObservationComponent::Vy => observed.vy = f64::MAX,
                            InvalidObservationComponent::Vz => observed.vz = f64::MAX,
                        }
                    }
                    observed
                })
                .collect()
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_rejects_invalid_config_payload() {
        let mut config = sample_config();
        config.gravity_x = f32::NAN;
        let mut driver = WorldDriver::new(vec![], Box::new(SimpleKinematicBackend::new()), config);

        let error = driver
            .step(TimelineId::new(), ObservationView::empty())
            .test_err();
        assert!(error.to_string().contains("world.config.v1"));
        assert!(error.to_string().contains("non-finite float value"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_rejects_non_finite_observation_payload() {
        assert_eq!(NonFiniteBackend.name(), "non-finite-test-backend");
        let entity = EntityId::new();
        let mut driver = WorldDriver::new(
            vec![Body {
                entity_id: entity,
                x: 0.0,
                y: 0.0,
                z: 0.0,
                vx: 0.0,
                vy: 0.0,
                vz: 0.0,
            }],
            Box::new(NonFiniteBackend),
            sample_config(),
        );

        let error = driver
            .step(TimelineId::new(), ObservationView::empty())
            .test_err();
        assert!(error.to_string().contains("world.observation.v1"));
        assert!(error.to_string().contains("non-finite float value"));
    }

    #[test]
    fn driver_rejects_non_finite_y_observation_payload() {
        let entity = EntityId::new();
        let mut driver = WorldDriver::new(
            vec![Body {
                entity_id: entity,
                x: 0.0,
                y: 0.0,
                z: 0.0,
                vx: 0.0,
                vy: 0.0,
                vz: 0.0,
            }],
            Box::new(YNonFiniteBackend),
            sample_config(),
        );
        let error = driver
            .step(TimelineId::new(), ObservationView::empty())
            .test_err();
        assert!(error.to_string().contains("non-finite float value"));
        driver.abort_step();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_rejects_coordinate_outside_f32_range() {
        let entity = EntityId::new();
        let mut driver = WorldDriver::new(
            vec![Body {
                entity_id: entity,
                x: 0.0,
                y: 0.0,
                z: 0.0,
                vx: 0.0,
                vy: 0.0,
                vz: 0.0,
            }],
            Box::new(OutOfRangeBackend),
            sample_config(),
        );
        let error = driver
            .step(TimelineId::new(), ObservationView::empty())
            .test_err();
        let message = error.to_string();
        assert!(
            message.contains("non-representable x coordinate")
                || message.contains("non-finite float value"),
            "unexpected coordinate error: {message}"
        );
        driver.abort_step();
    }

    #[test]
    fn invalid_backend_observation_components_fail_closed_and_restore_step() {
        for (component, axis) in [
            (InvalidObservationComponent::Z, "z"),
            (InvalidObservationComponent::Vx, "vx"),
            (InvalidObservationComponent::Vy, "vy"),
            (InvalidObservationComponent::Vz, "vz"),
        ] {
            let initial = Body {
                entity_id: EntityId::new(),
                x: 1.0,
                y: 2.0,
                z: 3.0,
                vx: 4.0,
                vy: 5.0,
                vz: 6.0,
            };
            let mut driver = WorldDriver::new(
                vec![initial],
                Box::new(InvalidObservationComponentBackend {
                    component,
                    first_step_invalid: std::sync::atomic::AtomicBool::new(true),
                }),
                sample_config(),
            );
            let error = driver
                .step(TimelineId::new(), ObservationView::empty())
                .test_err();
            assert!(error
                .to_string()
                .contains(&format!("non-representable {axis} coordinate")));

            let output = driver
                .step(TimelineId::new(), ObservationView::empty())
                .test_ok();
            assert_eq!(output.drafts.len(), 2);
            assert_eq!(output.drafts[0].event_type.as_str(), EVENT_TYPE_CONFIG_V1);
            let observation = WorldObservationV1::decode(&output.drafts[1].payload).test_ok();
            assert_eq!(observation.tick, 0);
            assert_eq!(observation.step_index, 0);
            assert!((observation.pos_x - 1.0).abs() < 0.05);
            assert!((observation.pos_y - 2.0).abs() < 0.05);
            assert!((observation.pos_z - 3.0).abs() < 0.05);
            assert_eq!(observation.vel_lin_x.to_bits(), 4.0_f32.to_bits());
            assert_eq!(observation.vel_lin_y.to_bits(), 5.0_f32.to_bits());
            assert_eq!(observation.vel_lin_z.to_bits(), 6.0_f32.to_bits());
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_round_trip() {
        let a = sample_action();
        let bytes = a.encode().test_ok();
        let decoded = WorldActionV1::decode(&bytes).test_ok();
        assert_eq!(decoded.actor_entity_id, a.actor_entity_id);
        assert_eq!(decoded.body_entity_id, a.body_entity_id);
        assert_eq!(decoded.action_kind, a.action_kind);
        assert_eq!(decoded.action_scope, a.action_scope);
        assert_eq!(decoded.params_cbor, a.params_cbor);
        assert_eq!(decoded.catalogue_version, a.catalogue_version);
        assert_eq!(decoded.tick, a.tick);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_target_velocity_allowed() {
        let mut a = sample_action();
        a.action_kind = ActionKindV1::TargetVelocity;
        let bytes = a.encode().test_ok();
        let decoded = WorldActionV1::decode(&bytes).test_ok();
        assert_eq!(decoded.action_kind, ActionKindV1::TargetVelocity);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_unknown_kind_rejected_on_decode() {
        // Build a WAC1 array with an unknown action_kind string via raw CBOR.
        let arr = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(b"WAC1".to_vec()),
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Bytes(vec![0u8; 16]),
            ciborium::Value::Bytes(vec![0u8; 16]),
            ciborium::Value::Text("unknown_kind".to_owned()),
            ciborium::Value::Bytes(encode_actuator_pair_v1(0.0, 0.0).test_ok()),
            ciborium::Value::Integer(0.into()),
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(0.into()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&arr, &mut buf).test_ok();
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::UnknownActionKind)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_invalid_scope_rejected_on_encode() {
        let mut a = sample_action();
        a.action_scope = 1; // joint — deferred in v1
        assert!(matches!(
            a.encode(),
            Err(WorldCodecError::InvalidActionScope)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_invalid_scope_rejected_on_decode() {
        let arr = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(b"WAC1".to_vec()),
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Bytes(vec![0u8; 16]),
            ciborium::Value::Bytes(vec![0u8; 16]),
            ciborium::Value::Text("impulse".to_owned()),
            ciborium::Value::Bytes(encode_actuator_pair_v1(0.0, 0.0).test_ok()),
            ciborium::Value::Integer(1.into()), // invalid scope
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(0.into()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&arr, &mut buf).test_ok();
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::InvalidActionScope)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_non_canonical_params_rejected() {
        let mut a = sample_action();
        // Non-canonical CBOR: two-byte encoding of integer 1 (canonical is one byte 0x01)
        a.params_cbor = vec![0x19, 0x00, 0x01];
        assert!(matches!(
            a.encode(),
            Err(WorldCodecError::NonCanonicalParamsCbor)
        ));
        for params in [
            vec![0xa2, 0x61, b'b', 1, 0x61, b'a', 2], // unsorted map keys
            vec![0xa2, 0x61, b'a', 1, 0x61, b'a', 2], // duplicate map key
            vec![0xa2, 0xf9, 0, 0, 1, 0xf9, 0x80, 0, 2], // equal signed-zero keys
            vec![0x81, 0xa2, 0x61, b'b', 1, 0x61, b'a', 2], // nested map
            vec![0xc1, 0xa2, 0x61, b'b', 1, 0x61, b'a', 2], // tagged map
            vec![0xf9, 0x7c, 0x00],                   // non-finite float
        ] {
            a.params_cbor = params;
            assert_eq!(a.encode(), Err(WorldCodecError::NonCanonicalParamsCbor));
        }

        a.params_cbor = encode_actuator_pair_v1(1.25, -2.5).test_ok();
        assert!(a.encode().is_ok());
        a.params_cbor = vec![0xff];
        assert!(matches!(
            a.encode(),
            Err(WorldCodecError::NonCanonicalParamsCbor)
        ));
    }

    #[test]
    fn velocity_parameter_decoder_accepts_a_canonical_pair() {
        let params = encode_horizontal_velocity_params(1.25, -2.5);
        assert_eq!(
            decode_horizontal_velocity_params(&params),
            Some((1.25, -2.5))
        );
    }

    #[test]
    fn velocity_parameter_decoder_rejects_invalid_components() {
        let invalid_first = cbor_encode(&ciborium::Value::Array(vec![
            ciborium::Value::Float(f64::NAN),
            ciborium::Value::Float(0.0),
        ]));
        assert_eq!(decode_horizontal_velocity_params(&invalid_first), None);

        let invalid_second = cbor_encode(&ciborium::Value::Array(vec![
            ciborium::Value::Float(0.0),
            ciborium::Value::Float(f64::INFINITY),
        ]));
        assert_eq!(decode_horizontal_velocity_params(&invalid_second), None);
    }

    #[test]
    fn actuator_pair_normalizes_float_sources_and_preserves_signed_zero() {
        let params = encode_actuator_pair_v1(1.0 / 3.0, -0.0).test_ok();
        let (x, z) = decode_horizontal_velocity_params(&params).test_ok();
        assert_eq!(x.to_bits(), 0.333_333_34_f32.to_bits());
        assert_eq!(z.to_bits(), (-0.0_f32).to_bits());
        assert_eq!(
            encode_actuator_pair_v1(f64::MIN_POSITIVE, -f64::MIN_POSITIVE).test_ok(),
            encode_actuator_pair_v1(0.0, -0.0).test_ok()
        );
        assert_eq!(
            encode_actuator_pair_v1(f64::INFINITY, 0.0),
            Err(WorldCodecError::NonFiniteFloat)
        );
        assert_eq!(
            encode_actuator_pair_v1(0.0, f64::MAX),
            Err(WorldCodecError::NonFiniteFloat)
        );

        let one = f32::from_bits(0x3f80_0000);
        let next = f32::from_bits(0x3f80_0001);
        let midpoint = f64::midpoint(f64::from(one), f64::from(next));
        let tie = encode_actuator_pair_v1(midpoint, 0.0).test_ok();
        assert_eq!(
            decode_horizontal_velocity_params(&tie)
                .test_ok()
                .0
                .to_bits(),
            one.to_bits()
        );

        let least_subnormal = f32::from_bits(1);
        assert_eq!(
            encode_actuator_pair_v1(1.0, f64::from(least_subnormal)).test_ok(),
            vec![0x82, 0xf9, 0x3c, 0x00, 0xfa, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn actuator_pair_rejects_unnormalized_and_wrong_shape_wire_inputs() {
        let mut action = sample_action();
        for params in [
            cbor_encode(&ciborium::Value::Array(vec![
                ciborium::Value::Float(1.0 / 3.0),
                ciborium::Value::Float(0.0),
            ])),
            cbor_encode(&ciborium::Value::Array(vec![
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Float(0.0),
            ])),
            cbor_encode(&ciborium::Value::Array(vec![
                ciborium::Value::Float(1.0),
                ciborium::Value::Float(0.0),
                ciborium::Value::Float(0.0),
            ])),
            cbor_encode(&ciborium::Value::Array(vec![
                ciborium::Value::Float(f64::MAX),
                ciborium::Value::Float(0.0),
            ])),
        ] {
            action.params_cbor = params;
            assert_eq!(
                action.encode(),
                Err(WorldCodecError::NonCanonicalParamsCbor)
            );
        }
    }

    #[test]
    fn world_action_v1_trailing_params_are_rejected() {
        let mut action = sample_action();
        action.params_cbor = vec![0xf6, 0x00];
        assert!(matches!(
            action.encode(),
            Err(WorldCodecError::NonCanonicalParamsCbor)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_wrong_field_type_on_decode() {
        // Put an integer where bytes are expected for actor_entity_id.
        let arr = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(b"WAC1".to_vec()),
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(99.into()), // wrong type for entity id
            ciborium::Value::Bytes(vec![0u8; 16]),
            ciborium::Value::Text("impulse".to_owned()),
            ciborium::Value::Bytes(vec![0xf6]),
            ciborium::Value::Integer(0.into()),
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(0.into()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&arr, &mut buf).test_ok();
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_rejects_wrong_numeric_and_params_types() {
        let action = sample_action();
        let encoded = action.encode().test_ok();
        for (index, replacement) in [
            (5, ciborium::Value::Integer(1.into())),
            (6, ciborium::Value::Text("not-a-number".to_owned())),
            (7, ciborium::Value::Text("not-a-number".to_owned())),
            (8, ciborium::Value::Text("not-a-number".to_owned())),
        ] {
            assert!(matches!(
                WorldActionV1::decode(&rewrite_array_field(&encoded, index, replacement)),
                Err(WorldCodecError::WrongFieldType)
            ));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_payload_too_large_rejected_on_encode_and_decode() {
        let mut action = sample_action();
        action.params_cbor = cbor_encode(&ciborium::Value::Bytes(vec![0; MAX_ACTION_BYTES]));
        assert!(matches!(
            action.encode(),
            Err(WorldCodecError::NonCanonicalParamsCbor)
        ));
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(vec![0; MAX_ACTION_BYTES + 1])),
            Err(WorldCodecError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_wrong_magic_rejected() {
        let a = sample_action();
        let mut bytes = a.encode().test_ok().as_slice().to_vec();
        // byte[2] is always 'W' in the magic (array-header, bytes-header, 'W', ...).
        bytes[2] = b'X';
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(WorldCodecError::WrongMagic)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_trailing_bytes_rejected() {
        let a = sample_action();
        let mut bytes = a.encode().test_ok().as_slice().to_vec();
        bytes.push(0x00);
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(WorldCodecError::TrailingBytes)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_empty_params_rejected() {
        let mut a = sample_action();
        a.params_cbor = vec![0xf6]; // CBOR null
        assert_eq!(a.encode(), Err(WorldCodecError::NonCanonicalParamsCbor));
    }

    // ---------------------------------------------------------------------------
    // WorldObservationV1 codec tests
    // ---------------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_round_trip() {
        let o = sample_observation();
        let bytes = o.encode().test_ok();
        let d = WorldObservationV1::decode(&bytes).test_ok();
        assert_eq!(d.body_entity_id, o.body_entity_id);
        assert_eq!(d.tick, o.tick);
        assert_eq!(d.step_index, o.step_index);
        assert!((d.pos_x - o.pos_x).abs() < f32::EPSILON);
        assert!((d.pos_y - o.pos_y).abs() < f32::EPSILON);
        assert!((d.pos_z - o.pos_z).abs() < f32::EPSILON);
        assert!((d.orient_w - o.orient_w).abs() < f32::EPSILON);
        assert!((d.orient_x - o.orient_x).abs() < f32::EPSILON);
        assert!((d.orient_y - o.orient_y).abs() < f32::EPSILON);
        assert!((d.orient_z - o.orient_z).abs() < f32::EPSILON);
        assert!((d.vel_lin_x - o.vel_lin_x).abs() < f32::EPSILON);
        assert!((d.vel_lin_y - o.vel_lin_y).abs() < f32::EPSILON);
        assert!((d.vel_lin_z - o.vel_lin_z).abs() < f32::EPSILON);
        assert!((d.vel_ang_x - o.vel_ang_x).abs() < f32::EPSILON);
        assert!((d.vel_ang_y - o.vel_ang_y).abs() < f32::EPSILON);
        assert!((d.vel_ang_z - o.vel_ang_z).abs() < f32::EPSILON);
        assert_eq!(d.sensor_kind, o.sensor_kind);
        assert_eq!(d.sensor_value, o.sensor_value);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_nan_pos_rejected_on_encode() {
        let mut o = sample_observation();
        o.pos_x = f32::NAN;
        assert!(matches!(o.encode(), Err(WorldCodecError::NonFiniteFloat)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_infinity_orient_rejected_on_encode() {
        let mut o = sample_observation();
        o.orient_x = f32::INFINITY;
        assert!(matches!(o.encode(), Err(WorldCodecError::NonFiniteFloat)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_non_finite_float_rejected_on_decode() {
        let o = sample_observation();
        let bytes = rewrite_array_field(&o.encode().test_ok(), 5, ciborium::Value::Float(f64::NAN));
        assert!(matches!(
            WorldObservationV1::decode(&bytes),
            Err(WorldCodecError::NonFiniteFloat)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_payload_too_large_rejected_on_encode() {
        let mut observation = sample_observation();
        observation.sensor_value = vec![0; MAX_SENSOR_VALUE_BYTES + 1];
        assert!(matches!(
            observation.encode(),
            Err(WorldCodecError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_wrong_magic_rejected() {
        let o = sample_observation();
        let mut bytes = o.encode().test_ok().as_slice().to_vec();
        // byte[2] is always 'W' in the magic (array-header, bytes-header, 'W', ...).
        bytes[2] = b'X';
        assert!(matches!(
            WorldObservationV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(WorldCodecError::WrongMagic)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_trailing_bytes_rejected() {
        let o = sample_observation();
        let mut bytes = o.encode().test_ok().as_slice().to_vec();
        bytes.push(0x00);
        assert!(matches!(
            WorldObservationV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(WorldCodecError::TrailingBytes)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_wrong_array_length_rejected() {
        let truncated = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(b"WOB1".to_vec()),
            ciborium::Value::Integer(1.into()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&truncated, &mut buf).test_ok();
        assert!(matches!(
            WorldObservationV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::WrongArrayLength)
        ));
    }

    // ---------------------------------------------------------------------------
    // WorldConfigV1 codec tests
    // ---------------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_round_trip() {
        let c = sample_config();
        let bytes = c.encode().test_ok();
        let decoded = WorldConfigV1::decode(&bytes).test_ok();
        assert_eq!(decoded.backend_id, c.backend_id);
        assert_eq!(decoded.backend_version, c.backend_version);
        assert_eq!(decoded.backend_content_hash, c.backend_content_hash);
        assert_eq!(decoded.timestep_micros, c.timestep_micros);
        assert_eq!(decoded.coord_convention, c.coord_convention);
        assert!((decoded.gravity_y - c.gravity_y).abs() < f32::EPSILON);
        assert_eq!(decoded.sensor_min_resolution_mm, c.sensor_min_resolution_mm);
        assert_eq!(
            decoded.actuator_catalogue_version,
            c.actuator_catalogue_version
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_wrong_magic_rejected() {
        let c = sample_config();
        let mut bytes = c.encode().test_ok().as_slice().to_vec();
        // byte[2] is always 'W' in the magic (array-header, bytes-header, 'W', ...).
        bytes[2] = b'X';
        assert!(matches!(
            WorldConfigV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(WorldCodecError::WrongMagic)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_trailing_bytes_rejected() {
        let c = sample_config();
        let mut bytes = c.encode().test_ok().as_slice().to_vec();
        bytes.push(0xFF);
        assert!(matches!(
            WorldConfigV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(WorldCodecError::TrailingBytes)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_non_finite_gravity_rejected() {
        let mut c = sample_config();
        c.gravity_y = f32::NAN;
        assert!(matches!(c.encode(), Err(WorldCodecError::NonFiniteFloat)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_invalid_coord_convention_rejected_on_encode() {
        let mut c = sample_config();
        c.coord_convention = 1; // only 0 is valid in v1
        assert!(matches!(
            c.encode(),
            Err(WorldCodecError::InvalidCoordConvention)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_invalid_coord_convention_rejected_on_decode() {
        // Build a WCF1 array with coord_convention = 1
        let mut c = sample_config();
        c.coord_convention = 0; // encode valid first
        let bytes = c.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).test_ok();
        if let ciborium::Value::Array(ref mut items) = val {
            items[3] = ciborium::Value::Integer(1.into()); // flip coord_convention
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            WorldConfigV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::InvalidCoordConvention)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_sensor_resolution_below_minimum_rejected_on_encode() {
        let mut c = sample_config();
        c.sensor_min_resolution_mm = 99; // below 100mm floor
        assert!(matches!(
            c.encode(),
            Err(WorldCodecError::SensorResolutionBelowMinimum)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_sensor_resolution_below_minimum_rejected_on_decode() {
        let c = sample_config();
        let bytes = c.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).test_ok();
        if let ciborium::Value::Array(ref mut items) = val {
            items[12] = ciborium::Value::Integer(50.into()); // below 100mm floor
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            WorldConfigV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::SensorResolutionBelowMinimum)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_wrong_field_type_for_backend_id_rejected() {
        let c = sample_config();
        let bytes = c.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).test_ok();
        if let ciborium::Value::Array(ref mut items) = val {
            items[7] = ciborium::Value::Integer(42.into()); // backend_id should be tstr
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            WorldConfigV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_rejects_wrong_hash_and_resolution_types() {
        let config = sample_config();
        let encoded = config.encode().test_ok();
        assert!(matches!(
            WorldConfigV1::decode(&rewrite_array_field(
                &encoded,
                9,
                ciborium::Value::Integer(42.into()),
            )),
            Err(WorldCodecError::WrongFieldType)
        ));
        assert!(matches!(
            WorldConfigV1::decode(&rewrite_array_field(
                &encoded,
                12,
                ciborium::Value::Text("not-a-number".to_owned()),
            )),
            Err(WorldCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_codecs_reject_non_array_cbor() {
        let scalar = CanonicalBytes::from_vec(cbor_encode(&ciborium::Value::Integer(1.into())));
        assert!(matches!(
            WorldActionV1::decode(&scalar),
            Err(WorldCodecError::CborError)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_wrong_field_type_for_float_rejected() {
        let o = sample_observation();
        let bytes = o.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).test_ok();
        if let ciborium::Value::Array(ref mut items) = val {
            items[5] = ciborium::Value::Text("not_a_float".to_owned()); // pos_x should be float
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            WorldObservationV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_payload_too_large_for_sensor_rejected() {
        let o = sample_observation();
        let bytes = o.encode().test_ok().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).test_ok();
        if let ciborium::Value::Array(ref mut items) = val {
            items[19] = ciborium::Value::Bytes(vec![0u8; MAX_SENSOR_VALUE_BYTES + 1]);
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        assert!(matches!(
            WorldObservationV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_encode_rejects_oversized_sensor_value() {
        let mut observation = sample_observation();
        observation.sensor_value = vec![0; MAX_SENSOR_VALUE_BYTES + 1];

        assert!(matches!(
            observation.encode(),
            Err(WorldCodecError::PayloadTooLarge { .. })
        ));
    }

    fn assert_config_decode_boundaries(config: &CanonicalBytes) {
        for (index, replacement) in [
            (0, ciborium::Value::Integer(1.into())),
            (1, ciborium::Value::Text("version".to_owned())),
            (2, ciborium::Value::Text("timestep".to_owned())),
            (3, ciborium::Value::Text("convention".to_owned())),
            (4, ciborium::Value::Text("gravity".to_owned())),
            (5, ciborium::Value::Text("gravity".to_owned())),
            (6, ciborium::Value::Text("gravity".to_owned())),
            (7, ciborium::Value::Integer(1.into())),
            (8, ciborium::Value::Integer(1.into())),
            (9, ciborium::Value::Integer(1.into())),
            (10, ciborium::Value::Text("action-schema".to_owned())),
            (11, ciborium::Value::Text("observation-schema".to_owned())),
            (12, ciborium::Value::Text("resolution".to_owned())),
            (13, ciborium::Value::Text("catalogue".to_owned())),
        ] {
            assert!(
                WorldConfigV1::decode(&rewrite_array_field(config, index, replacement)).is_err()
            );
        }
        assert!(WorldConfigV1::decode(&rewrite_array_field(
            config,
            2,
            ciborium::Value::Integer(u64::MAX.into()),
        ))
        .is_err());
        assert!(WorldConfigV1::decode(&rewrite_array_field(
            config,
            12,
            ciborium::Value::Integer(u64::MAX.into()),
        ))
        .is_err());
        for mutate in [
            |value: &mut WorldConfigV1| value.gravity_x = f32::NAN,
            |value: &mut WorldConfigV1| value.gravity_y = f32::NAN,
            |value: &mut WorldConfigV1| value.gravity_z = f32::NAN,
        ] {
            let mut invalid = sample_config();
            mutate(&mut invalid);
            assert!(matches!(
                invalid.encode(),
                Err(WorldCodecError::NonFiniteFloat)
            ));
        }
    }

    #[test]
    fn world_codecs_cover_each_typed_decode_boundary() {
        let action = sample_action().encode().test_ok();
        for (index, replacement) in [
            (0, ciborium::Value::Integer(1.into())),
            (1, ciborium::Value::Text("version".to_owned())),
            (2, ciborium::Value::Integer(1.into())),
            (3, ciborium::Value::Integer(1.into())),
            (4, ciborium::Value::Integer(1.into())),
            (5, ciborium::Value::Integer(1.into())),
            (6, ciborium::Value::Text("scope".to_owned())),
            (7, ciborium::Value::Text("catalogue".to_owned())),
            (8, ciborium::Value::Text("tick".to_owned())),
        ] {
            assert!(
                WorldActionV1::decode(&rewrite_array_field(&action, index, replacement)).is_err()
            );
        }
        assert!(WorldActionV1::decode(&rewrite_array_field(
            &action,
            6,
            ciborium::Value::Integer(u64::MAX.into()),
        ))
        .is_err());
        assert!(WorldActionV1::decode(&rewrite_array_field(
            &action,
            7,
            ciborium::Value::Integer(u64::MAX.into()),
        ))
        .is_err());

        let observation = sample_observation().encode().test_ok();
        for index in 0..20 {
            assert!(WorldObservationV1::decode(&rewrite_array_field(
                &observation,
                index,
                ciborium::Value::Text("wrong".to_owned()),
            ))
            .is_err());
        }

        let float_positions = [
            |value: &mut WorldObservationV1| value.pos_x = f32::NAN,
            |value: &mut WorldObservationV1| value.pos_y = f32::NAN,
            |value: &mut WorldObservationV1| value.pos_z = f32::NAN,
            |value: &mut WorldObservationV1| value.orient_w = f32::NAN,
            |value: &mut WorldObservationV1| value.orient_x = f32::NAN,
            |value: &mut WorldObservationV1| value.orient_y = f32::NAN,
            |value: &mut WorldObservationV1| value.orient_z = f32::NAN,
            |value: &mut WorldObservationV1| value.vel_lin_x = f32::NAN,
            |value: &mut WorldObservationV1| value.vel_lin_y = f32::NAN,
            |value: &mut WorldObservationV1| value.vel_lin_z = f32::NAN,
            |value: &mut WorldObservationV1| value.vel_ang_x = f32::NAN,
            |value: &mut WorldObservationV1| value.vel_ang_y = f32::NAN,
            |value: &mut WorldObservationV1| value.vel_ang_z = f32::NAN,
        ];
        for mutate in float_positions {
            let mut invalid = sample_observation();
            mutate(&mut invalid);
            assert!(matches!(
                invalid.encode(),
                Err(WorldCodecError::NonFiniteFloat)
            ));
        }
        let config = sample_config().encode().test_ok();
        assert_config_decode_boundaries(&config);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_driver_emits_config_on_first_step() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![], backend, sample_config());
        let out = driver.step(tl.id(), ObservationView::empty()).test_ok();
        // First step: config draft only (no bodies)
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_CONFIG_V1);
        // Second step: no config, no bodies
        let out2 = driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(out2.drafts.len(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_driver_default_is_constructible() {
        let driver = WorldDriver::default();
        assert_eq!(driver.name(), "world-driver");
        assert!(driver.entities.is_empty());
    }

    #[test]
    fn world_driver_recovers_versioned_history_atomically() {
        let body = EntityId::new();
        let config_entity = EntityId::new();
        let timeline = TimelineId::new();
        let mut params = Vec::new();
        ciborium::into_writer(&vec![1.0_f32, 0.0_f32], &mut params).test_ok();
        let action = WorldActionV1 {
            actor_entity_id: body,
            body_entity_id: body,
            action_kind: ActionKindV1::TargetVelocity,
            params_cbor: params,
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let observation = WorldObservationV1 {
            body_entity_id: body,
            tick: 0,
            step_index: 0,
            pos_x: 1.0,
            pos_y: 2.0,
            pos_z: 0.0,
            orient_w: 1.0,
            orient_x: 0.0,
            orient_y: 0.0,
            orient_z: 0.0,
            vel_lin_x: 1.0,
            vel_lin_y: 0.0,
            vel_lin_z: 0.0,
            vel_ang_x: 0.0,
            vel_ang_y: 0.0,
            vel_ang_z: 0.0,
            sensor_kind: 0,
            sensor_value: vec![],
        };
        let events = vec![
            make_versioned_event(
                1,
                config_entity,
                EVENT_TYPE_CONFIG_V1,
                sample_config().encode().test_ok(),
            ),
            make_versioned_event(2, body, EVENT_TYPE_ACTION_V1, action.encode().test_ok()),
            make_versioned_event(
                3,
                body,
                EVENT_TYPE_OBSERVATION_V1,
                observation.encode().test_ok(),
            ),
            make_versioned_event(
                4,
                body,
                "other.event",
                CanonicalBytes::from_static(b"other"),
            ),
        ];
        let plugin = WorldPlugin::new().with_bodies([body]);
        let mut registry = PluginRegistry::new()
            .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
        registry
            .register(
                &plugin,
                Some(Box::new(WorldReducer)),
                Some(Box::new(
                    WorldDriver::new(
                        vec![Body {
                            entity_id: body,
                            x: 0.0,
                            y: 0.0,
                            z: 0.0,
                            vx: 0.0,
                            vy: 0.0,
                            vz: 0.0,
                        }],
                        Box::new(SimpleKinematicBackend::new()),
                        sample_config(),
                    )
                    .with_config_entity(config_entity),
                )),
            )
            .test_ok();
        registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(4))],
                &events,
            )
            .test_ok();
        registry
            .step_all_anchored_with_events(timeline, Seq::from_u64(4), &events)
            .test_ok();
        registry.abort_step();
        registry
            .step_all_anchored_with_events(timeline, Seq::from_u64(4), &events)
            .test_ok();
        let mut reduced = WorldReducer.initial();
        WorldReducer.apply(&mut reduced, &events[2]);
        assert_eq!(reduced.get("last_x"), Some(&serde_json::json!(1.0)));
        registry.commit_step_at(Seq::ZERO, 0).test_ok();
    }

    fn assert_malformed_recovery_events(
        registry: &mut PluginRegistry,
        timeline: TimelineId,
        body: EntityId,
    ) {
        for event_type in [EVENT_TYPE_ACTION_V1, EVENT_TYPE_OBSERVATION_V1] {
            let malformed = make_versioned_event(
                1,
                body,
                event_type,
                CanonicalBytes::from_static(b"malformed"),
            );
            assert!(registry
                .restore_driver_state(
                    &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
                    &[malformed],
                )
                .is_err());
        }

        let unknown_target_action = WorldActionV1 {
            actor_entity_id: body,
            body_entity_id: EntityId::new(),
            action_kind: ActionKindV1::Impulse,
            params_cbor: encode_horizontal_velocity_params(1.0, 0.0),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let unknown_target = make_versioned_event(
            1,
            body,
            EVENT_TYPE_ACTION_V1,
            unknown_target_action.encode().test_ok(),
        );
        assert!(registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
                &[unknown_target],
            )
            .is_err());

        let mut unknown_observation = sample_observation();
        unknown_observation.body_entity_id = EntityId::new();
        let unknown_target_observation = make_versioned_event(
            1,
            body,
            EVENT_TYPE_OBSERVATION_V1,
            unknown_observation.encode().test_ok(),
        );
        assert!(registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
                &[unknown_target_observation],
            )
            .is_ok());
    }

    fn assert_recovery_sequence(
        registry: &mut PluginRegistry,
        timeline: TimelineId,
        body: EntityId,
    ) {
        let mut first_action = WorldActionV1 {
            actor_entity_id: body,
            body_entity_id: body,
            action_kind: ActionKindV1::Impulse,
            params_cbor: encode_horizontal_velocity_params(1.0, 0.0),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let first = make_versioned_event(
            1,
            body,
            EVENT_TYPE_ACTION_V1,
            first_action.encode().test_ok(),
        );
        first_action.tick = 1;
        let second = make_versioned_event(
            2,
            body,
            EVENT_TYPE_ACTION_V1,
            first_action.encode().test_ok(),
        );
        registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(2))],
                &[first, second],
            )
            .test_ok();

        let malformed_config = make_versioned_event(
            1,
            body,
            EVENT_TYPE_CONFIG_V1,
            CanonicalBytes::from_static(b"malformed"),
        );
        assert!(registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
                &[malformed_config],
            )
            .is_err());

        let mut mismatched_config = sample_config();
        mismatched_config.backend_id = "different-backend".to_owned();
        let mismatched_config = make_versioned_event(
            1,
            body,
            EVENT_TYPE_CONFIG_V1,
            mismatched_config.encode().test_ok(),
        );
        assert!(registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
                &[mismatched_config],
            )
            .is_err());
    }

    #[test]
    fn world_driver_rejects_malformed_recovery_payloads() {
        let body = EntityId::new();
        let timeline = TimelineId::new();
        let plugin = WorldPlugin::new().with_bodies([body]);
        let mut registry = PluginRegistry::new()
            .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
        registry
            .register(
                &plugin,
                Some(Box::new(WorldReducer)),
                Some(Box::new(WorldDriver::new(
                    vec![Body {
                        entity_id: body,
                        x: 0.0,
                        y: 0.0,
                        z: 0.0,
                        vx: 0.0,
                        vy: 0.0,
                        vz: 0.0,
                    }],
                    Box::new(SimpleKinematicBackend::new()),
                    sample_config(),
                ))),
            )
            .test_ok();
        assert_malformed_recovery_events(&mut registry, timeline, body);
        assert_recovery_sequence(&mut registry, timeline, body);
        let mut reduced = WorldReducer.initial();
        WorldReducer.apply(
            &mut reduced,
            &make_versioned_event(
                1,
                body,
                EVENT_TYPE_OBSERVATION_V1,
                CanonicalBytes::from_static(b"malformed"),
            ),
        );
        let mut direct_driver = WorldDriver::default();
        direct_driver.commit_restore_from_history();
        direct_driver.abort_step();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_driver_default_emits_its_default_config() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("default-driver").test_ok();
        let mut driver = WorldDriver::default();

        let output = driver.step(tl.id(), ObservationView::empty()).test_ok();
        let config = WorldConfigV1::decode(&output.drafts[0].payload).test_ok();

        assert_eq!(config.backend_id, "simple-kinematic");
        assert_eq!(config.backend_version, "1.0.0");
        assert!((config.gravity_y + 9.81).abs() < f32::EPSILON);
        assert_eq!(config.sensor_min_resolution_mm, SENSOR_MIN_RESOLUTION_MM);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_codec_error_is_debug() {
        let e = WorldCodecError::WrongMagic;
        assert!(!format!("{e:?}").is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_codec_error_display() {
        assert!(!WorldCodecError::NonFiniteFloat.to_string().is_empty());
        assert!(!WorldCodecError::TrailingBytes.to_string().is_empty());
        assert!(!WorldCodecError::CborError.to_string().is_empty());
        assert!(!WorldCodecError::WrongVersion.to_string().is_empty());
        assert!(!WorldCodecError::WrongArrayLength.to_string().is_empty());
        assert!(!WorldCodecError::WrongFieldType.to_string().is_empty());
        assert!(!WorldCodecError::UnknownActionKind.to_string().is_empty());
        assert!(!format!(
            "{}",
            WorldCodecError::PayloadTooLarge {
                size: 5000,
                max: MAX_ACTION_BYTES
            }
        )
        .is_empty());
    }

    fn flip_version(bytes: &[u8]) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(bytes);
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).test_ok();
        if let ciborium::Value::Array(ref mut items) = val {
            items[1] = ciborium::Value::Integer(99_i64.into());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).test_ok();
        buf
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_wrong_version_rejected() {
        let o = sample_observation();
        let flipped = flip_version(o.encode().test_ok().as_slice());
        assert!(matches!(
            WorldObservationV1::decode(&CanonicalBytes::from_vec(flipped)),
            Err(WorldCodecError::WrongVersion)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_wrong_version_rejected() {
        let a = sample_action();
        let flipped = flip_version(a.encode().test_ok().as_slice());
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(flipped)),
            Err(WorldCodecError::WrongVersion)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_wrong_version_rejected() {
        let c = sample_config();
        let flipped = flip_version(c.encode().test_ok().as_slice());
        assert!(matches!(
            WorldConfigV1::decode(&CanonicalBytes::from_vec(flipped)),
            Err(WorldCodecError::WrongVersion)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_invalid_cbor_rejected() {
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(vec![0xFF, 0xFF])),
            Err(WorldCodecError::CborError)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_new_and_default() {
        let p1 = WorldPlugin::new();
        let p2 = WorldPlugin::default();
        assert_eq!(p1.name(), "world");
        assert_eq!(p2.name(), "world");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_name_is_world() {
        let plugin = WorldPlugin::new();
        assert_eq!(plugin.name(), "world");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_id_is_returned() {
        let plugin = WorldPlugin::new();
        let _id = plugin.id();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability_is_correct() {
        let plugin = WorldPlugin::new();
        let cap = plugin.capability();

        assert_eq!(cap.owned_event_types.len(), 3);
        assert_eq!(cap.owned_event_types[0].as_str(), EVENT_TYPE_ACTION_V1);
        assert_eq!(cap.owned_event_types[1].as_str(), EVENT_TYPE_OBSERVATION_V1);
        assert_eq!(cap.owned_event_types[2].as_str(), EVENT_TYPE_CONFIG_V1);
        assert_eq!(cap.owned_entity_kinds.len(), 1);
        assert_eq!(cap.owned_entity_kinds[0], ENTITY_KIND);
        assert!(cap.has_driver);
        assert!(cap.has_reducer);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_new() {
        let backend = SimpleKinematicBackend::new();
        assert_eq!(backend.name(), "simple-kinematic");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_name_is_correct() {
        let backend = SimpleKinematicBackend::new();
        assert_eq!(backend.name(), "simple-kinematic");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_step_moves_bodies() {
        let backend = SimpleKinematicBackend::new();
        let entity = EntityId::new();
        let bodies = vec![Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            vx: 1.0,
            vy: 2.0,
            vz: 0.0,
        }];

        let observations = backend.step(&bodies, 1_000_000);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].entity_id, entity);
        assert!((observations[0].x - 1.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_step_multiple_bodies() {
        let backend = SimpleKinematicBackend::new();
        let entity1 = EntityId::new();
        let entity2 = EntityId::new();
        let bodies = vec![
            Body {
                entity_id: entity1,
                x: 0.0,
                y: 0.0,
                z: 0.0,
                vx: 1.0,
                vy: 0.0,
                vz: 0.0,
            },
            Body {
                entity_id: entity2,
                x: 10.0,
                y: 10.0,
                z: 0.0,
                vx: -1.0,
                vy: -1.0,
                vz: 0.0,
            },
        ];

        let observations = backend.step(&bodies, 1_000_000);
        assert_eq!(observations.len(), 2);
        assert!((observations[0].x - 1.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 0.0).abs() < f64::EPSILON);
        assert!((observations[1].x - 9.0).abs() < f64::EPSILON);
        assert!((observations[1].y - 9.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_steps_named_world_coordinates() {
        let capability = pos_core::WorldGeographicEvidenceCapabilityV1::for_trusted_core();
        let origin = pos_core::WorldOriginV1::new(
            &capability,
            [21; 16],
            [22; 16],
            1,
            pos_core::Wgs84PositionV1::new(35.0, -120.0, 100.0).test_ok(),
            [23; 32],
            10_000.0,
        )
        .test_ok();
        let transform = pos_core::WorldTransformV1::new(&capability, origin).test_ok();
        let position = transform
            .forward(
                &capability,
                pos_core::Wgs84PositionV1::new(35.001, -119.999, 120.0).test_ok(),
            )
            .test_ok();
        let body = WorldCoordinateBody::new(EntityId::new(), position, 1.5, -2.0, 0.25);
        assert!((body.position().east_metres() - position.east_metres()).abs() < f64::EPSILON);
        assert!((body.position().north_metres() - position.north_metres()).abs() < f64::EPSILON);
        assert!((body.position().up_metres() - position.up_metres()).abs() < f64::EPSILON);

        let backend = SimpleKinematicBackend::new();
        let observations = backend.step_coordinates(&[body]).test_ok();

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].entity_id(), body.entity_id());
        assert!(
            (observations[0].position().east_metres() - (position.east_metres() + 1.5)).abs()
                < f64::EPSILON
        );
        assert!(
            (observations[0].position().north_metres() - (position.north_metres() - 2.0)).abs()
                < f64::EPSILON
        );
        assert!(
            (observations[0].position().up_metres() - (position.up_metres() + 0.25)).abs()
                < f64::EPSILON
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_rejects_non_finite_coordinate_steps() {
        let capability = pos_core::WorldGeographicEvidenceCapabilityV1::for_trusted_core();
        let origin = pos_core::WorldOriginV1::new(
            &capability,
            [24; 16],
            [25; 16],
            1,
            pos_core::Wgs84PositionV1::new(35.0, -120.0, 100.0).test_ok(),
            [26; 32],
            10_000.0,
        )
        .test_ok();
        let transform = pos_core::WorldTransformV1::new(&capability, origin).test_ok();
        let position = transform
            .forward(
                &capability,
                pos_core::Wgs84PositionV1::new(35.001, -119.999, 120.0).test_ok(),
            )
            .test_ok();
        let body = WorldCoordinateBody::new(EntityId::new(), position, f64::INFINITY, 0.0, 0.0);
        let backend = SimpleKinematicBackend::new();

        assert!(matches!(
            backend.step_coordinates(&[body]),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_name_is_correct() {
        let backend = Box::new(SimpleKinematicBackend::new());
        let driver = WorldDriver::new(vec![], backend, sample_config());
        assert_eq!(driver.name(), "world-driver");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_step_produces_correct_event_type() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            vx: 1.0,
            vy: 1.0,
            vz: 0.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend, sample_config());

        // First step: config (index 0) + observation (index 1).
        let out = driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(out.drafts.len(), 2);
        assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_CONFIG_V1);
        assert_eq!(out.drafts[1].event_type.as_str(), EVENT_TYPE_OBSERVATION_V1);
        // Second step: observation only.
        let out2 = driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(out2.drafts.len(), 1);
        assert_eq!(
            out2.drafts[0].event_type.as_str(),
            EVENT_TYPE_OBSERVATION_V1
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_step_produces_decodable_v1_payload() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 5.0,
            y: 10.0,
            z: 0.0,
            vx: 2.0,
            vy: 3.0,
            vz: 0.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend, sample_config());

        // First step: drafts[0]=config, drafts[1]=observation.
        let out = driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(out.drafts.len(), 2);
        let obs = WorldObservationV1::decode(&out.drafts[1].payload).test_ok();
        // Positions are quantized to sensor_min_resolution_mm (100mm = 0.1m).
        let expected_x = (7.0_f32 / 0.1).round() * 0.1;
        let expected_y = (13.0_f32 / 0.1).round() * 0.1;
        assert!((obs.pos_x - expected_x).abs() < 0.001);
        assert!((obs.pos_y - expected_y).abs() < 0.001);
        assert_eq!(obs.tick, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_updates_body_positions() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            vx: 1.0,
            vy: 1.0,
            vz: 0.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend, sample_config());

        driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert!((driver.entities[0].x - 1.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 1.0).abs() < f64::EPSILON);

        driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert!((driver.entities[0].x - 2.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 2.0).abs() < f64::EPSILON);
    }

    struct UnknownEntityBackend;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl WorldBackend for UnknownEntityBackend {
        fn name(&self) -> &'static str {
            "unknown-entity"
        }

        fn step(&self, _bodies: &[Body], _timestep_micros: u32) -> Vec<WorldObservation> {
            vec![WorldObservation {
                entity_id: EntityId::new(),
                x: 9.0,
                y: 9.0,
                z: 9.0,
                vx: 0.0,
                vy: 0.0,
                vz: 0.0,
            }]
        }
    }

    struct MixedEntityBackend {
        extra: EntityId,
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl WorldBackend for MixedEntityBackend {
        fn name(&self) -> &'static str {
            "mixed-entity"
        }

        fn step(&self, bodies: &[Body], _timestep_micros: u32) -> Vec<WorldObservation> {
            let mut out: Vec<WorldObservation> = bodies
                .iter()
                .map(|body| WorldObservation {
                    entity_id: body.entity_id,
                    x: body.x + body.vx,
                    y: body.y + body.vy,
                    z: body.z + body.vz,
                    vx: body.vx,
                    vy: body.vy,
                    vz: body.vz,
                })
                .collect();
            out.push(WorldObservation {
                entity_id: self.extra,
                x: 0.0,
                y: 0.0,
                z: 0.0,
                vx: 0.0,
                vy: 0.0,
                vz: 0.0,
            });
            out
        }
    }

    struct ReversedObservationBackend;

    impl WorldBackend for ReversedObservationBackend {
        fn name(&self) -> &'static str {
            "reversed-observation-test-backend"
        }

        fn step(&self, bodies: &[Body], timestep_micros: u32) -> Vec<WorldObservation> {
            let mut observations = SimpleKinematicBackend::new().step(bodies, timestep_micros);
            observations.reverse();
            observations
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_rejects_observations_for_unknown_entities() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let known = EntityId::new();
        let body = Body {
            entity_id: known,
            x: 1.0,
            y: 2.0,
            z: 0.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        };
        let mut driver =
            WorldDriver::new(vec![body], Box::new(UnknownEntityBackend), sample_config());
        assert_eq!(UnknownEntityBackend.name(), "unknown-entity");
        let error = driver.step(tl.id(), ObservationView::empty()).test_err();
        assert!(error
            .to_string()
            .contains("backend observation body set differs from staged bodies"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_rejects_mixed_known_and_unknown_backend_observations() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let known = EntityId::new();
        let unknown = EntityId::new();
        let body = Body {
            entity_id: known,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            vx: 1.0,
            vy: 2.0,
            vz: 0.0,
        };
        let mut driver = WorldDriver::new(
            vec![body],
            Box::new(MixedEntityBackend { extra: unknown }),
            sample_config(),
        );
        assert_eq!(MixedEntityBackend { extra: unknown }.name(), "mixed-entity");
        let error = driver.step(tl.id(), ObservationView::empty()).test_err();
        assert!(error
            .to_string()
            .contains("backend observation body set differs from staged bodies"));
    }

    #[test]
    fn driver_rejects_duplicate_staged_bodies() {
        let body = Body {
            entity_id: EntityId::new(),
            x: 0.0,
            y: 0.0,
            z: 0.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        };
        let mut driver = WorldDriver::new(
            vec![body.clone(), body],
            Box::new(SimpleKinematicBackend::new()),
            sample_config(),
        );
        let error = driver
            .step(TimelineId::new(), ObservationView::empty())
            .test_err();
        assert!(error
            .to_string()
            .contains("duplicate staged body identifiers"));
    }

    #[test]
    fn driver_emits_observations_in_entity_id_order() {
        let mut ids = [EntityId::new(), EntityId::new()];
        ids.sort_unstable();
        let first = Body {
            entity_id: ids[0],
            x: 1.0,
            y: 2.0,
            z: 3.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        };
        let second = Body {
            entity_id: ids[1],
            ..first.clone()
        };
        let mut driver = WorldDriver::new(
            vec![second, first],
            Box::new(ReversedObservationBackend),
            sample_config(),
        );
        let output = driver
            .step(TimelineId::new(), ObservationView::empty())
            .test_ok();
        let observed_ids: Vec<_> = output
            .drafts
            .iter()
            .filter(|draft| draft.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .map(|draft| {
                WorldObservationV1::decode(&draft.payload)
                    .test_ok()
                    .body_entity_id
            })
            .collect();
        assert_eq!(observed_ids, ids);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_initial_state_has_correct_fields() {
        let reducer = WorldReducer;
        let state = reducer.initial();
        assert!(state.get("observation_count").is_some());
        assert!(state.get("body_count").is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_tracks_observation_count() {
        let reducer = WorldReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        assert_eq!(
            state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );

        for _ in 0..5 {
            let event = make_observation_event(entity);
            reducer.apply(&mut state, &event);
        }

        assert_eq!(
            state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64),
            Some(5)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_ignores_other_event_types() {
        let reducer = WorldReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let other = make_other_event(entity);
        reducer.apply(&mut state, &other);

        assert_eq!(
            state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );

        let legacy = make_versioned_event(
            1,
            entity,
            "world.observation",
            make_observation_event(entity).payload,
        );
        reducer.apply(&mut state, &legacy);
        let malformed = make_versioned_event(
            2,
            entity,
            EVENT_TYPE_OBSERVATION_V1,
            CanonicalBytes::from_vec(vec![0xff]),
        );
        reducer.apply(&mut state, &malformed);
        assert_eq!(
            state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert!(state.get("last_x").is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_rejects_parseable_noncanonical_wob1() {
        let reducer = WorldReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();
        let canonical = make_observation_event(entity);
        let noncanonical = make_versioned_event(
            1,
            entity,
            EVENT_TYPE_OBSERVATION_V1,
            overlong_version(&canonical.payload),
        );
        reducer.apply(&mut state, &noncanonical);
        assert_eq!(
            state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert!(state.get("last_x").is_none());

        reducer.apply(&mut state, &canonical);
        assert_eq!(
            state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            state.get("last_x").and_then(serde_json::Value::as_f64),
            Some(1.0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn body_partial_eq() {
        let entity = EntityId::new();
        let b1 = Body {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
            z: 0.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        };
        let b2 = Body {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
            z: 0.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        };
        let b3 = Body {
            entity_id: entity,
            x: 3.0,
            y: 4.0,
            z: 0.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        };
        assert_eq!(b1, b2);
        assert_ne!(b1, b3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_partial_eq() {
        let entity = EntityId::new();
        let o1 = WorldObservation {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
            z: 3.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        };
        let o2 = WorldObservation {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
            z: 3.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        };
        let o3 = WorldObservation {
            entity_id: entity,
            x: 3.0,
            y: 4.0,
            z: 5.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        };
        assert_eq!(o1, o2);
        assert_ne!(o1, o3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_empty_bodies_produces_no_events() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![], backend, sample_config());

        // First step: config event only (no bodies → no observations).
        let out = driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_CONFIG_V1);
        // Second step: no config, no bodies → no events.
        let out2 = driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(out2.drafts.len(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backend_step_with_zero_velocity() {
        let backend = SimpleKinematicBackend::new();
        let entity = EntityId::new();
        let bodies = vec![Body {
            entity_id: entity,
            x: 5.0,
            y: 7.0,
            z: 0.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        }];

        let observations = backend.step(&bodies, 1_000_000);
        assert_eq!(observations.len(), 1);
        assert!((observations[0].x - 5.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backend_step_with_negative_velocity() {
        let backend = SimpleKinematicBackend::new();
        let entity = EntityId::new();
        let bodies = vec![Body {
            entity_id: entity,
            x: 10.0,
            y: 10.0,
            z: 0.0,
            vx: -2.0,
            vy: -3.0,
            vz: 0.0,
        }];

        let observations = backend.step(&bodies, 1_000_000);
        assert_eq!(observations.len(), 1);
        assert!((observations[0].x - 8.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_tick_increments() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            vx: 1.0,
            vy: 1.0,
            vz: 0.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend, sample_config());

        assert_eq!(driver.tick, 0);
        driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(driver.tick, 1);
        driver.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(driver.tick, 2);
    }

    // ---------------------------------------------------------------------------
    // Conformance fixtures (A5)
    // ---------------------------------------------------------------------------

    mod conformance_fixtures {
        use super::*;

        #[test]
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn simplekinematic_conformance_fixture() {
            let entity = EntityId::new();
            let body = Body {
                entity_id: entity,
                x: 0.0,
                y: 0.0,
                z: 0.0,
                vx: 1.5,
                vy: -0.5,
                vz: 0.0,
            };

            // With resolution_mm=100 (0.1m), both 1.5 and -0.5 are exact multiples.
            let expected_pos_x = (1.5_f32 / 0.1).round() * 0.1;
            let expected_pos_y = (-0.5_f32 / 0.1).round() * 0.1;

            // First independent run.
            let mut store1 = open_store(StoreConfig::Memory).test_ok();
            let tl1 = store1.create_timeline("fixture-1").test_ok();
            let mut driver1 = WorldDriver::new(
                vec![body.clone()],
                Box::new(SimpleKinematicBackend::new()),
                sample_config(),
            );
            let out1 = driver1.step(tl1.id(), ObservationView::empty()).test_ok();
            // drafts[0]=config, drafts[1]=observation
            assert_eq!(out1.drafts.len(), 2);
            let obs1 = WorldObservationV1::decode(&out1.drafts[1].payload).test_ok();
            assert!((obs1.pos_x - expected_pos_x).abs() < 0.001);
            assert!((obs1.pos_y - expected_pos_y).abs() < 0.001);

            // Second independent run — same input must produce same output (determinism).
            let mut store2 = open_store(StoreConfig::Memory).test_ok();
            let tl2 = store2.create_timeline("fixture-2").test_ok();
            let mut driver2 = WorldDriver::new(
                vec![body],
                Box::new(SimpleKinematicBackend::new()),
                sample_config(),
            );
            let out2 = driver2.step(tl2.id(), ObservationView::empty()).test_ok();
            assert_eq!(out2.drafts.len(), 2);
            let obs2 = WorldObservationV1::decode(&out2.drafts[1].payload).test_ok();
            assert!((obs2.pos_x - expected_pos_x).abs() < 0.001);
            assert!((obs2.pos_y - expected_pos_y).abs() < 0.001);
            // Byte-identical payloads prove determinism.
            assert_eq!(
                out1.drafts[1].payload.as_slice(),
                out2.drafts[1].payload.as_slice()
            );
        }

        #[test]
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn worlddriver_observation_encodes_sensor_proximity() {
            let mut store = open_store(StoreConfig::Memory).test_ok();
            let tl = store.create_timeline("sensor-kind-test").test_ok();
            let entity = EntityId::new();
            let body = Body {
                entity_id: entity,
                x: 0.0,
                y: 0.0,
                z: 0.0,
                vx: 1.0,
                vy: 0.0,
                vz: 0.0,
            };
            let mut driver = WorldDriver::new(
                vec![body],
                Box::new(SimpleKinematicBackend::new()),
                sample_config(),
            );
            let out = driver.step(tl.id(), ObservationView::empty()).test_ok();
            // drafts[0]=config, drafts[1]=observation
            assert_eq!(out.drafts.len(), 2);
            let obs = WorldObservationV1::decode(&out.drafts[1].payload).test_ok();
            assert_eq!(obs.sensor_kind, SensorKindV1::Proximity.as_u8());
        }
    }

    // -----------------------------------------------------------------------
    // A3: action folding tests
    // -----------------------------------------------------------------------

    fn make_action_event_from(entity: EntityId, action: &WorldActionV1) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_ACTION_V1),
            payload: action.encode().test_ok(),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    fn encode_horizontal_velocity_params(x: f32, z: f32) -> Vec<u8> {
        cbor_encode(&ciborium::Value::Array(vec![
            cbor_f32(x).test_ok(),
            cbor_f32(z).test_ok(),
        ]))
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_plugin_builders_and_accessors() {
        let body_id = EntityId::new();
        let plugin = WorldPlugin::new()
            .with_catalogue_version(2)
            .with_allowed_actions(vec!["custom_action".to_owned()])
            .with_bodies(vec![body_id]);

        assert_eq!(plugin.catalogue_version(), 2);
        assert_eq!(plugin.allowed_action_kinds, vec!["custom_action"]);
        assert!(plugin.known_bodies.contains(&body_id));

        let mut plugin2 = WorldPlugin::default();
        let body_id2 = EntityId::new();
        plugin2.add_body(body_id2);
        assert!(plugin2.known_bodies.contains(&body_id2));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_applies_impulse_action_to_body() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            vx: 1.0,
            vy: 0.0,
            vz: 0.0,
        };
        let mut driver = WorldDriver::new(
            vec![body],
            Box::new(SimpleKinematicBackend::new()),
            sample_config(),
        );

        // Impulse changes X/Z velocity; vertical Y remains unchanged.
        let action = WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: entity,
            action_kind: ActionKindV1::Impulse,
            params_cbor: encode_horizontal_velocity_params(0.5, 2.0),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let events = vec![
            make_other_event(entity),
            make_action_event_from(entity, &action),
        ];
        let out = driver
            .step(tl.id(), ObservationView::from_events(&events))
            .test_ok();
        let obs_draft = out
            .drafts
            .iter()
            .find(|d| d.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .test_ok();
        let obs = WorldObservationV1::decode(&obs_draft.payload).test_ok();
        // Position floor does not apply to velocity.
        assert!((obs.pos_x - 1.5_f32).abs() < 0.15);
        assert!((obs.pos_z - 2.0_f32).abs() < 0.15);
        assert_eq!(obs.pos_y.to_bits(), 0.0_f32.to_bits());
        assert_eq!(obs.vel_lin_x.to_bits(), 1.5_f32.to_bits());
        assert_eq!(obs.vel_lin_y.to_bits(), 0.0_f32.to_bits());
        assert_eq!(obs.vel_lin_z.to_bits(), 2.0_f32.to_bits());

        // The host supplies the complete committed prefix on every Tick. The
        // same impulse must not be applied a second time when that prefix is
        // replayed for the next step.
        driver.commit_step();
        let out = driver
            .step(tl.id(), ObservationView::from_events(&events))
            .test_ok();
        let obs_draft = out
            .drafts
            .iter()
            .find(|d| d.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .test_ok();
        let obs = WorldObservationV1::decode(&obs_draft.payload).test_ok();
        assert!((obs.pos_x - 3.0_f32).abs() < 0.15);
        assert!((obs.pos_z - 4.0_f32).abs() < 0.15);
        assert_eq!(obs.pos_y.to_bits(), 0.0_f32.to_bits());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_applies_target_velocity_action() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        // High initial velocity; TargetVelocity must override it entirely.
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            vx: 10.0,
            vy: 10.0,
            vz: 0.0,
        };
        let mut driver = WorldDriver::new(
            vec![body],
            Box::new(SimpleKinematicBackend::new()),
            sample_config(),
        );

        // TargetVelocity overrides horizontal X/Z while retaining vertical Y.
        let action = WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: entity,
            action_kind: ActionKindV1::TargetVelocity,
            params_cbor: encode_horizontal_velocity_params(2.0, 0.5),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let events = vec![make_action_event_from(entity, &action)];
        let out = driver
            .step(tl.id(), ObservationView::from_events(&events))
            .test_ok();
        let obs_draft = out
            .drafts
            .iter()
            .find(|d| d.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .test_ok();
        let obs = WorldObservationV1::decode(&obs_draft.payload).test_ok();
        assert!((obs.pos_x - 2.0_f32).abs() < 0.15);
        assert!((obs.pos_z - 0.5_f32).abs() < 0.15);
        assert!((obs.pos_y - 10.0_f32).abs() < 0.15);
        assert_eq!(obs.vel_lin_x.to_bits(), 2.0_f32.to_bits());
        assert_eq!(obs.vel_lin_y.to_bits(), 10.0_f32.to_bits());
        assert_eq!(obs.vel_lin_z.to_bits(), 0.5_f32.to_bits());
    }

    #[test]
    fn horizontal_actuators_use_pinned_timestep_without_velocity_quantization() {
        let body_id = EntityId::new();
        let mut config = sample_config();
        config.timestep_micros = 250_000;
        let mut driver = WorldDriver::new(
            vec![Body {
                entity_id: body_id,
                x: 0.0,
                y: 3.0,
                z: 0.0,
                vx: 0.0,
                vy: 1.0,
                vz: 0.0,
            }],
            Box::new(SimpleKinematicBackend::new()),
            config,
        );
        let action = WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: body_id,
            action_kind: ActionKindV1::TargetVelocity,
            params_cbor: encode_actuator_pair_v1(0.0625, -0.125).test_ok(),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let output = driver
            .step(
                TimelineId::new(),
                ObservationView::from_events(&[make_action_event_from(body_id, &action)]),
            )
            .test_ok();
        let mut observation = WorldObservationV1::decode(&output.drafts[1].payload).test_ok();
        assert_eq!(observation.pos_x, 0.0);
        assert_eq!(observation.pos_z, 0.0);
        assert_eq!(observation.vel_lin_x.to_bits(), 0.0625_f32.to_bits());
        assert_eq!(observation.vel_lin_y.to_bits(), 1.0_f32.to_bits());
        assert_eq!(observation.vel_lin_z.to_bits(), (-0.125_f32).to_bits());

        // Four quarter-second steps must accumulate the unquantized backend
        // position. Quantizing state after each step would still report zero.
        for _ in 0..3 {
            driver.commit_step();
            let output = driver
                .step(TimelineId::new(), ObservationView::empty())
                .test_ok();
            observation = WorldObservationV1::decode(&output.drafts[0].payload).test_ok();
        }
        assert_eq!(observation.tick, 3);
        assert_eq!(observation.step_index, 3);
        assert!((observation.pos_x - 0.1).abs() < 0.001);
        assert!((observation.pos_y - 4.0).abs() < 0.001);
        assert!((observation.pos_z + 0.1).abs() < 0.001);
    }

    #[test]
    fn driver_rejects_action_catalogue_outside_pinned_configuration() {
        let body_id = EntityId::new();
        let actor_id = EntityId::new();
        let plugin = WorldPlugin::new()
            .with_bodies([body_id])
            .with_catalogue_version(2);
        let action = WorldActionV1 {
            actor_entity_id: actor_id,
            body_entity_id: body_id,
            action_kind: ActionKindV1::Impulse,
            params_cbor: encode_actuator_pair_v1(1.0, 0.0).test_ok(),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 2,
            tick: 0,
        };
        let proposal = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor_id,
            action.encode().test_ok(),
            Kind::new("world.action.v1.submit"),
        );
        plugin.approve(&proposal).test_ok();

        let mut driver = WorldDriver::new(
            vec![Body {
                entity_id: body_id,
                x: 0.0,
                y: 0.0,
                z: 0.0,
                vx: 0.0,
                vy: 0.0,
                vz: 0.0,
            }],
            Box::new(SimpleKinematicBackend::new()),
            sample_config(),
        );
        let error = driver
            .step(
                TimelineId::new(),
                ObservationView::from_events(&[make_action_event_from(body_id, &action)]),
            )
            .test_err();
        assert!(error
            .to_string()
            .contains("action catalogue version differs from pinned world configuration"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_updates_causation_for_repeated_actions_on_one_body() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let mut driver = WorldDriver::new(
            vec![Body {
                entity_id: entity,
                x: 0.0,
                y: 0.0,
                z: 0.0,
                vx: 0.0,
                vy: 0.0,
                vz: 0.0,
            }],
            Box::new(SimpleKinematicBackend::new()),
            sample_config(),
        );
        let action = WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: entity,
            action_kind: ActionKindV1::Impulse,
            params_cbor: encode_horizontal_velocity_params(1.0, 0.0),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let mut first = make_action_event_from(entity, &action);
        first.seq = Seq::from_u64(1);
        let mut second = make_action_event_from(entity, &action);
        second.seq = Seq::from_u64(2);
        let events = vec![first, second];
        let output = driver
            .step(tl.id(), ObservationView::from_events(&events))
            .test_ok();
        let observation = output
            .drafts
            .iter()
            .find(|draft| draft.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .test_ok();
        assert!(WorldObservationV1::decode(&observation.payload).is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_rejects_malformed_action_payload() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            vx: 1.0,
            vy: 1.0,
            vz: 0.0,
        };
        let mut driver = WorldDriver::new(
            vec![body],
            Box::new(SimpleKinematicBackend::new()),
            sample_config(),
        );

        let bad_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_ACTION_V1),
            payload: CanonicalBytes::from_vec(vec![0xFF, 0xFE, 0xFD]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        let events = vec![bad_event];
        let error = driver
            .step(tl.id(), ObservationView::from_events(&events))
            .test_err();
        match error {
            RuntimeError::InvalidPayload { event_type, reason } => {
                assert_eq!(event_type, EVENT_TYPE_ACTION_V1);
                assert_eq!(reason, "CBOR decode error");
            }
            other => std::panic::resume_unwind(Box::new(format!("unexpected error: {other:?}"))),
        }
        driver.abort_step();
    }

    #[test]
    fn failed_action_batch_can_retry_without_partial_world_state() {
        let body_id = EntityId::new();
        let initial = Body {
            entity_id: body_id,
            x: 1.0,
            y: 2.0,
            z: 3.0,
            vx: 0.0,
            vy: 4.0,
            vz: 0.0,
        };
        let mut driver = WorldDriver::new(
            vec![initial],
            Box::new(SimpleKinematicBackend::new()),
            sample_config(),
        );
        let action = WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: body_id,
            action_kind: ActionKindV1::Impulse,
            params_cbor: encode_actuator_pair_v1(1.0, 2.0).test_ok(),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let accepted = make_action_event_from(body_id, &action);
        let mut malformed = make_action_event_from(body_id, &action);
        malformed.seq = Seq::from_u64(1);
        malformed.payload = CanonicalBytes::from_static(b"malformed");
        let error = driver
            .step(
                TimelineId::new(),
                ObservationView::from_events(&[accepted.clone(), malformed]),
            )
            .test_err();
        assert!(error.to_string().contains("world.action.v1"));

        let output = driver
            .step(TimelineId::new(), ObservationView::from_events(&[accepted]))
            .test_ok();
        assert_eq!(output.drafts.len(), 2);
        assert_eq!(output.drafts[0].event_type.as_str(), EVENT_TYPE_CONFIG_V1);
        let observation = WorldObservationV1::decode(&output.drafts[1].payload).test_ok();
        assert_eq!(observation.tick, 0);
        assert_eq!(observation.step_index, 0);
        assert!((observation.pos_x - 2.0).abs() < 0.05);
        assert!((observation.pos_y - 6.0).abs() < 0.05);
        assert!((observation.pos_z - 5.0).abs() < 0.05);
        assert_eq!(observation.vel_lin_x.to_bits(), 1.0_f32.to_bits());
        assert_eq!(observation.vel_lin_y.to_bits(), 4.0_f32.to_bits());
        assert_eq!(observation.vel_lin_z.to_bits(), 2.0_f32.to_bits());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_rejects_unknown_action_target_and_parameters() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            z: 0.0,
            vx: 0.0,
            vy: 0.0,
            vz: 0.0,
        };
        let mut driver = WorldDriver::new(
            vec![body],
            Box::new(SimpleKinematicBackend::new()),
            sample_config(),
        );

        let unknown_target = WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: EntityId::new(),
            action_kind: ActionKindV1::Impulse,
            params_cbor: encode_horizontal_velocity_params(1.0, 1.0),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let error = driver
            .step(
                tl.id(),
                ObservationView::from_events(&[make_action_event_from(entity, &unknown_target)]),
            )
            .test_err();
        assert!(matches!(error, RuntimeError::InvalidPayload { .. }));
        driver.abort_step();

        let valid_parameters = WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: entity,
            action_kind: ActionKindV1::Impulse,
            params_cbor: encode_horizontal_velocity_params(1.0, 0.0),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let mut invalid_parameters = make_action_event_from(entity, &valid_parameters);
        invalid_parameters.payload = rewrite_array_field(
            &invalid_parameters.payload,
            5,
            ciborium::Value::Bytes(vec![0xf6]),
        );
        let error = driver
            .step(tl.id(), ObservationView::from_events(&[invalid_parameters]))
            .test_err();
        assert!(matches!(error, RuntimeError::InvalidPayload { .. }));
        driver.abort_step();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_plugin_v1_approver_enforces_capability_and_domain() {
        let actor = EntityId::new();
        let body = EntityId::new();
        let plugin = WorldPlugin::new().with_bodies(vec![body]);
        let mut action = sample_action();
        action.actor_entity_id = actor;
        action.body_entity_id = body;
        action.catalogue_version = 1;
        let payload = action.encode().test_ok();

        let valid = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            payload.clone(),
            Kind::new("world.action.v1.submit"),
        );
        let valid_result = plugin.approve(&valid);
        assert!(
            valid_result.is_ok(),
            "v1 valid proposal rejected: {valid_result:?}"
        );

        let legacy = ProposedAction::new(
            Kind::new("world.action"),
            actor,
            payload.clone(),
            Kind::new("world.action.submit"),
        );
        assert_eq!(
            plugin.approve(&legacy),
            Err(ActionRejected::UnknownEventType)
        );

        let noncanonical_outer = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            overlong_version(&payload),
            Kind::new("world.action.v1.submit"),
        );
        assert_eq!(
            plugin.approve(&noncanonical_outer),
            Err(ActionRejected::DomainValidationFailed(
                WorldCodecError::NonCanonicalRecord.to_string()
            ))
        );

        let noncanonical_params = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            rewrite_array_field(&payload, 5, ciborium::Value::Bytes(vec![0x18, 0x01])),
            Kind::new("world.action.v1.submit"),
        );
        assert_eq!(
            plugin.approve(&noncanonical_params),
            Err(ActionRejected::DomainValidationFailed(
                WorldCodecError::NonCanonicalParamsCbor.to_string()
            ))
        );

        let wrong_capability = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            payload,
            Kind::new("world.action.submit"),
        );
        assert_eq!(
            plugin.approve(&wrong_capability),
            Err(ActionRejected::CapabilityNotGranted)
        );

        let too_large = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            CanonicalBytes::from_vec(vec![0; MAX_PROPOSED_ACTION_PAYLOAD_BYTES + 1]),
            Kind::new("world.action.v1.submit"),
        );
        assert!(matches!(
            plugin.approve(&too_large),
            Err(ActionRejected::PayloadTooLarge { .. })
        ));

        let malformed = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            CanonicalBytes::from_vec(vec![0xff]),
            Kind::new("world.action.v1.submit"),
        );
        assert!(matches!(
            plugin.approve(&malformed),
            Err(ActionRejected::DomainValidationFailed(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_plugin_v1_approver_rejects_noncanonical_map_params() {
        let actor = EntityId::new();
        let body = EntityId::new();
        let plugin = WorldPlugin::new().with_bodies(vec![body]);
        let mut action = sample_action();
        action.actor_entity_id = actor;
        action.body_entity_id = body;
        action.catalogue_version = 1;
        let payload = action.encode().test_ok();

        for params in [
            vec![0xa2, 0x61, b'b', 1, 0x61, b'a', 2],
            vec![0xa2, 0x61, b'a', 1, 0x61, b'a', 2],
            vec![0xa2, 0xf9, 0, 0, 1, 0xf9, 0x80, 0, 2],
            vec![0x81, 0xa2, 0x61, b'b', 1, 0x61, b'a', 2],
        ] {
            let proposal = ProposedAction::new(
                Kind::new(EVENT_TYPE_ACTION_V1),
                actor,
                rewrite_array_field(&payload, 5, ciborium::Value::Bytes(params)),
                Kind::new("world.action.v1.submit"),
            );
            assert_eq!(
                plugin.approve(&proposal),
                Err(ActionRejected::DomainValidationFailed(
                    WorldCodecError::NonCanonicalParamsCbor.to_string()
                ))
            );
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_plugin_v1_approver_enforces_domain_boundaries() {
        let actor = EntityId::new();
        let body = EntityId::new();
        let plugin = WorldPlugin::new().with_bodies(vec![body]);
        let mut action = sample_action();
        action.actor_entity_id = actor;
        action.body_entity_id = body;
        action.catalogue_version = 1;
        let payload = action.encode().test_ok();

        let mut wrong_actor_action = action.clone();
        wrong_actor_action.actor_entity_id = EntityId::new();
        let wrong_actor = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            wrong_actor_action.encode().test_ok(),
            Kind::new("world.action.v1.submit"),
        );
        assert_eq!(
            plugin.approve(&wrong_actor),
            Err(ActionRejected::InvalidActorEntityId)
        );

        let wrong_scope = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            rewrite_array_field(&payload, 6, ciborium::Value::Integer(1.into())),
            Kind::new("world.action.v1.submit"),
        );
        assert!(matches!(
            plugin.approve(&wrong_scope),
            Err(ActionRejected::DomainValidationFailed(_))
        ));

        let mut wrong_catalogue_action = action.clone();
        wrong_catalogue_action.catalogue_version = 99;
        let wrong_catalogue = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            wrong_catalogue_action.encode().test_ok(),
            Kind::new("world.action.v1.submit"),
        );
        assert!(matches!(
            plugin.approve(&wrong_catalogue),
            Err(ActionRejected::DomainValidationFailed(_))
        ));

        let mut wrong_kind_action = action.clone();
        wrong_kind_action.action_kind = ActionKindV1::TargetVelocity;
        let wrong_kind = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            wrong_kind_action.encode().test_ok(),
            Kind::new("world.action.v1.submit"),
        );
        let restricted = WorldPlugin::new()
            .with_bodies(vec![body])
            .with_allowed_actions(vec!["impulse".to_owned()]);
        assert!(matches!(
            restricted.approve(&wrong_kind),
            Err(ActionRejected::DomainValidationFailed(_))
        ));

        let mut unknown_body_action = action;
        unknown_body_action.body_entity_id = EntityId::new();
        let unknown_body = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            unknown_body_action.encode().test_ok(),
            Kind::new("world.action.v1.submit"),
        );
        assert!(matches!(
            plugin.approve(&unknown_body),
            Err(ActionRejected::DomainValidationFailed(_))
        ));
    }
}
