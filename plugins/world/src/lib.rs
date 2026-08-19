#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-world` — spatial + embodiment plugin (rapier-free stub for Wave 5).
//!
//! Owns event types `"world.observation"`, `"world.action"` and entity kind `"world-body"`.
//! For Wave 5 we build the interface and a simple 2D position model (no rapier dependency —
//! rapier is deferred to Wave 6 when we need 3D physics).
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_core::{
    event::{CanonicalBytes, Event, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
    WorldCoordinateV1, WorldTransformError,
};
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};
use serde::{Deserialize, Serialize};

/// The entity kind string for world bodies.
pub const ENTITY_KIND: &str = "world-body";

/// The event type for world observations.
pub const EVENT_TYPE_OBSERVATION: &str = "world.observation";

/// The event type for world actions.
pub const EVENT_TYPE_ACTION: &str = "world.action";

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
#[derive(Debug, Clone, PartialEq)]
pub enum ActionKindV1 {
    Impulse,
    TargetVelocity,
}

impl ActionKindV1 {
    fn as_str(&self) -> &str {
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
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SensorKindV1 {
    Proximity = 0,
    ContactCount = 1,
}

impl SensorKindV1 {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Errors returned by world CBOR codec encode/decode operations.
#[derive(Debug, PartialEq, thiserror::Error)]
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
    #[error("params_cbor is not canonical CBOR")]
    NonCanonicalParamsCbor,
    #[error("trailing bytes after CBOR item")]
    TrailingBytes,
    #[error("CBOR decode error")]
    CborError,
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

fn cbor_magic(magic: &[u8; 4]) -> ciborium::Value {
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

fn decode_magic(val: &ciborium::Value, expected: &[u8; 4]) -> Result<(), WorldCodecError> {
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
            let arr: [u8; 16] = b.as_slice().try_into().unwrap();
            let n = u128::from_be_bytes(arr);
            Ok(EntityId::from_ulid(ulid::Ulid::from(n)))
        }
        _ => Err(WorldCodecError::WrongFieldType),
    }
}

fn decode_bytes_fixed<const N: usize>(val: &ciborium::Value) -> Result<[u8; N], WorldCodecError> {
    match val {
        ciborium::Value::Bytes(b) if b.len() == N => Ok(b.as_slice().try_into().unwrap()),
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
    ciborium::into_writer(value, &mut buf).expect("Vec<u8> write is infallible");
    buf
}

fn cbor_decode_array(
    bytes: &[u8],
    expected_len: usize,
) -> Result<Vec<ciborium::Value>, WorldCodecError> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: ciborium::Value =
        ciborium::from_reader(&mut cursor).map_err(|_| WorldCodecError::CborError)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(WorldCodecError::TrailingBytes);
    }
    match value {
        ciborium::Value::Array(items) if items.len() == expected_len => Ok(items),
        ciborium::Value::Array(_) => Err(WorldCodecError::WrongArrayLength),
        _ => Err(WorldCodecError::CborError),
    }
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

fn decode_finite_f32(val: &ciborium::Value) -> Result<f32, WorldCodecError> {
    match val {
        ciborium::Value::Float(f) => {
            #[allow(clippy::cast_possible_truncation)]
            let v = *f as f32;
            if !v.is_finite() {
                Err(WorldCodecError::NonFiniteFloat)
            } else {
                Ok(v)
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
// WorldActionV1 — CBOR definite array, magic WAC1 (ADR-047 v3)
// ---------------------------------------------------------------------------

/// A versioned world action command (ADR-047 v3, `world.action.v1`).
///
/// Array (9 elements):
/// `[magic_bstr4, version_u8=1, actor_id_bstr16, body_id_bstr16,
///   action_kind_tstr, params_cbor_bstr, action_scope_u8, catalogue_version_u32, tick_u64]`
///
/// Max total encoded size: 4,096 bytes. `action_scope` must be `ACTION_SCOPE_SINGLE_BODY` in v1.
#[derive(Debug, Clone, PartialEq)]
pub struct WorldActionV1 {
    pub actor_entity_id: EntityId,
    pub body_entity_id: EntityId,
    pub action_kind: ActionKindV1,
    /// Canonical CBOR bytes for action parameters. Must be valid canonical CBOR.
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
    /// Returns [`WorldCodecError::NonCanonicalParamsCbor`] if `params_cbor` is not valid canonical CBOR.
    /// Returns [`WorldCodecError::PayloadTooLarge`] if the encoded payload exceeds 4,096 bytes.
    pub fn encode(&self) -> Result<CanonicalBytes, WorldCodecError> {
        if self.action_scope != ACTION_SCOPE_SINGLE_BODY {
            return Err(WorldCodecError::InvalidActionScope);
        }
        // Validate params_cbor is canonical: parse and re-encode must match.
        {
            let mut cursor = std::io::Cursor::new(self.params_cbor.as_slice());
            let parsed: ciborium::Value = ciborium::from_reader(&mut cursor)
                .map_err(|_| WorldCodecError::NonCanonicalParamsCbor)?;
            if cursor.position() != self.params_cbor.len() as u64 {
                return Err(WorldCodecError::NonCanonicalParamsCbor);
            }
            let reencoded = cbor_encode(&parsed);
            if reencoded != self.params_cbor {
                return Err(WorldCodecError::NonCanonicalParamsCbor);
            }
        }
        let arr = ciborium::Value::Array(vec![
            cbor_magic(MAGIC_WAC1),
            cbor_u8(VERSION_V1),
            cbor_id(self.actor_entity_id),
            cbor_id(self.body_entity_id),
            cbor_tstr(self.action_kind.as_str()),
            cbor_bytes(&self.params_cbor),
            cbor_u8(self.action_scope),
            cbor_u32(self.catalogue_version),
            cbor_u64(self.tick),
        ]);
        let encoded = cbor_encode(&arr);
        if encoded.len() > MAX_ACTION_BYTES {
            return Err(WorldCodecError::PayloadTooLarge {
                size: encoded.len(),
                max: MAX_ACTION_BYTES,
            });
        }
        Ok(CanonicalBytes::from_vec(encoded))
    }

    /// Decode from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns a [`WorldCodecError`] on any malformed input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, WorldCodecError> {
        if bytes.len() > MAX_ACTION_BYTES {
            return Err(WorldCodecError::PayloadTooLarge {
                size: bytes.len(),
                max: MAX_ACTION_BYTES,
            });
        }
        let items = cbor_decode_array(bytes.as_slice(), 9)?;
        decode_magic(&items[0], MAGIC_WAC1)?;
        decode_version(&items[1])?;
        let actor_entity_id = decode_id(&items[2])?;
        let body_entity_id = decode_id(&items[3])?;
        let kind_str = decode_tstr(&items[4])?;
        let action_kind =
            ActionKindV1::from_str(&kind_str).ok_or(WorldCodecError::UnknownActionKind)?;
        let params_cbor = decode_bytes_max(&items[5], MAX_ACTION_BYTES)?;
        let action_scope = decode_u8(&items[6])?;
        if action_scope != ACTION_SCOPE_SINGLE_BODY {
            return Err(WorldCodecError::InvalidActionScope);
        }
        let catalogue_version = decode_u32(&items[7])?;
        let tick = decode_u64(&items[8])?;
        Ok(Self {
            actor_entity_id,
            body_entity_id,
            action_kind,
            params_cbor,
            action_scope,
            catalogue_version,
            tick,
        })
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
            cbor_magic(MAGIC_WOB1),
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
        decode_magic(&items[0], MAGIC_WOB1)?;
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
            cbor_magic(MAGIC_WCF1),
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
        decode_magic(&items[0], MAGIC_WCF1)?;
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

fn decode_velocity_params(params: &[u8]) -> Option<(f32, f32)> {
    let items = cbor_decode_array(params, 2).ok()?;
    let vx = decode_finite_f32(&items[0]).ok()?;
    let vy = decode_finite_f32(&items[1]).ok()?;
    Some((vx, vy))
}

// ---------------------------------------------------------------------------
// World backend trait (physics seam)
// ---------------------------------------------------------------------------

/// A swappable physics backend.
///
/// For Wave 5 we provide a simple kinematic backend. Wave 6 will add rapier-based 3D physics.
pub trait WorldBackend: Send + Sync {
    /// Human-readable name for this backend.
    fn name(&self) -> &'static str;

    /// Simulate one step and return observations for all bodies.
    fn step(&mut self, bodies: &[Body]) -> Vec<WorldObservation>;
}

/// A body in the world.
#[derive(Debug, Clone, PartialEq)]
pub struct Body {
    pub entity_id: EntityId,
    pub x: f64,
    pub y: f64,
    pub vx: f64,
    pub vy: f64,
}

/// An observation of a body's position.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorldObservation {
    pub entity_id: EntityId,
    pub x: f64,
    pub y: f64,
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

/// Simple Euler integration: x += vx, y += vy per step (no physics).
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
        &mut self,
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

    fn step(&mut self, bodies: &[Body]) -> Vec<WorldObservation> {
        bodies
            .iter()
            .map(|body| WorldObservation {
                entity_id: body.entity_id,
                x: body.x + body.vx,
                y: body.y + body.vy,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorldObservationPayload {
    entity_id: String,
    x: f64,
    y: f64,
}

// ---------------------------------------------------------------------------
// Plugin descriptor
// ---------------------------------------------------------------------------

/// World simulation plugin.
pub struct WorldPlugin {
    id: PluginId,
}

impl Default for WorldPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl WorldPlugin {
    /// Create a new world plugin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: PluginId::new(),
        }
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
                Kind::new(EVENT_TYPE_OBSERVATION),
                Kind::new(EVENT_TYPE_ACTION),
            ],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: true,
            has_reducer: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Produces `world.config.v1` once on the first tick and `world.observation.v1` per body per step.
pub struct WorldDriver {
    entities: Vec<Body>,
    backend: Box<dyn WorldBackend>,
    tick: u64,
    /// Counts simulation steps independently of timeline ticks (same value in V1).
    step_index: u64,
    config: WorldConfigV1,
    config_emitted: bool,
}

impl WorldDriver {
    /// Create a new world driver with the given backend and session config.
    #[must_use]
    pub fn new(entities: Vec<Body>, backend: Box<dyn WorldBackend>, config: WorldConfigV1) -> Self {
        Self {
            entities,
            backend,
            tick: 0,
            step_index: 0,
            config,
            config_emitted: false,
        }
    }

    /// Quantize a raw sensor value to the session's minimum resolution.
    ///
    /// Values are rounded to the nearest multiple of `sensor_min_resolution_mm` millimetres.
    fn quantize_sensor(raw: f32, resolution_mm: u16) -> f32 {
        let r = f32::from(resolution_mm) / 1_000.0; // mm → metres
        (raw / r).round() * r
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

    fn step(
        &mut self,
        _timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        let mut drafts = Vec::new();

        // Emit world.config.v1 once at session creation (first step).
        if !self.config_emitted {
            let config_payload = self.config.encode().map_err(|_| RuntimeError::StepFailed)?;
            // Use EntityId::new() as the config event's entity — config is session-global.
            drafts.push(pos_core::event::EventDraft::new(
                EntityId::new(),
                Kind::new(EVENT_TYPE_CONFIG_V1),
                config_payload,
            ));
            self.config_emitted = true;
        }

        // Fold world.action.v1 events (in seq order) into entity velocities before
        // stepping the backend.
        for event in observations.events() {
            if event.event_type.as_str() != EVENT_TYPE_ACTION_V1 {
                continue;
            }
            let action = match WorldActionV1::decode(&event.payload) {
                Ok(a) => a,
                Err(_) => continue,
            };
            if let Some(body) = self
                .entities
                .iter_mut()
                .find(|b| b.entity_id == action.body_entity_id)
            {
                match action.action_kind {
                    ActionKindV1::Impulse => {
                        if let Some((dvx, dvy)) = decode_velocity_params(&action.params_cbor) {
                            body.vx += f64::from(dvx);
                            body.vy += f64::from(dvy);
                        }
                    }
                    ActionKindV1::TargetVelocity => {
                        if let Some((vx, vy)) = decode_velocity_params(&action.params_cbor) {
                            body.vx = f64::from(vx);
                            body.vy = f64::from(vy);
                        }
                    }
                }
            }
        }

        let step_obs = self.backend.step(&self.entities);

        // Update entities with new positions.
        for obs in &step_obs {
            if let Some(body) = self
                .entities
                .iter_mut()
                .find(|b| b.entity_id == obs.entity_id)
            {
                body.x = obs.x;
                body.y = obs.y;
            }
        }

        // Emit world.observation.v1 drafts with sensor quantization (ADR-047 v3).
        let resolution_mm = self.config.sensor_min_resolution_mm;
        for obs in &step_obs {
            #[allow(clippy::cast_possible_truncation)]
            let v1 = WorldObservationV1 {
                body_entity_id: obs.entity_id,
                tick: self.tick,
                // step_index tracks simulation steps; equals tick in the V1 single-backend model.
                step_index: self.step_index,
                pos_x: Self::quantize_sensor(obs.x as f32, resolution_mm),
                pos_y: Self::quantize_sensor(obs.y as f32, resolution_mm),
                pos_z: 0.0,
                orient_w: 1.0,
                orient_x: 0.0,
                orient_y: 0.0,
                orient_z: 0.0,
                vel_lin_x: 0.0,
                vel_lin_y: 0.0,
                vel_lin_z: 0.0,
                vel_ang_x: 0.0,
                vel_ang_y: 0.0,
                vel_ang_z: 0.0,
                sensor_kind: SensorKindV1::Proximity.as_u8(),
                sensor_value: vec![],
            };
            let payload = v1.encode().map_err(|_| RuntimeError::StepFailed)?;
            drafts.push(pos_core::event::EventDraft::new(
                obs.entity_id,
                Kind::new(EVENT_TYPE_OBSERVATION_V1),
                payload,
            ));
        }

        self.tick = self.tick.wrapping_add(1);
        self.step_index = self.step_index.wrapping_add(1);
        Ok(StepOutput::new(drafts))
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
        if event.event_type.as_str() == EVENT_TYPE_OBSERVATION {
            let observation_count = state
                .get("observation_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set(
                "observation_count",
                serde_json::Value::Number((observation_count + 1).into()),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, SchemaVersion},
        ids::{EntityId, EventId},
    };
    use pos_store::{open_store, StoreConfig};

    fn make_observation_event(entity: EntityId) -> Event {
        let payload = WorldObservationPayload {
            entity_id: entity.to_string(),
            x: 1.0,
            y: 2.0,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_OBSERVATION),
            payload: CanonicalBytes::from_vec(buf),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
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
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    // ---------------------------------------------------------------------------
    // WorldActionV1 codec tests
    // ---------------------------------------------------------------------------

    fn sample_action() -> WorldActionV1 {
        WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: EntityId::new(),
            action_kind: ActionKindV1::Impulse,
            params_cbor: vec![0xf6], // CBOR null — minimal valid canonical CBOR
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
            timestep_micros: 16_667,
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

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_round_trip() {
        let a = sample_action();
        let bytes = a.encode().unwrap();
        let decoded = WorldActionV1::decode(&bytes).unwrap();
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
        let bytes = a.encode().unwrap();
        let decoded = WorldActionV1::decode(&bytes).unwrap();
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
            ciborium::Value::Bytes(vec![0xf6]),
            ciborium::Value::Integer(0.into()),
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(0.into()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&arr, &mut buf).unwrap();
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
            ciborium::Value::Bytes(vec![0xf6]),
            ciborium::Value::Integer(1.into()), // invalid scope
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(0.into()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&arr, &mut buf).unwrap();
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
        ciborium::into_writer(&arr, &mut buf).unwrap();
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_wrong_magic_rejected() {
        let a = sample_action();
        let mut bytes = a.encode().unwrap().as_slice().to_vec();
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
        let mut bytes = a.encode().unwrap().as_slice().to_vec();
        bytes.push(0x00);
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(WorldCodecError::TrailingBytes)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_empty_params_allowed() {
        let mut a = sample_action();
        a.params_cbor = vec![0xf6]; // CBOR null
        let bytes = a.encode().unwrap();
        let decoded = WorldActionV1::decode(&bytes).unwrap();
        assert_eq!(decoded.params_cbor, vec![0xf6]);
    }

    // ---------------------------------------------------------------------------
    // WorldObservationV1 codec tests
    // ---------------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_round_trip() {
        let o = sample_observation();
        let bytes = o.encode().unwrap();
        let d = WorldObservationV1::decode(&bytes).unwrap();
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
    fn world_observation_v1_wrong_magic_rejected() {
        let o = sample_observation();
        let mut bytes = o.encode().unwrap().as_slice().to_vec();
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
        let mut bytes = o.encode().unwrap().as_slice().to_vec();
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
        ciborium::into_writer(&truncated, &mut buf).unwrap();
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
        let bytes = c.encode().unwrap();
        let decoded = WorldConfigV1::decode(&bytes).unwrap();
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
        let mut bytes = c.encode().unwrap().as_slice().to_vec();
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
        let mut bytes = c.encode().unwrap().as_slice().to_vec();
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
        let bytes = c.encode().unwrap().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();
        if let ciborium::Value::Array(ref mut items) = val {
            items[3] = ciborium::Value::Integer(1.into()); // flip coord_convention
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
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
        let bytes = c.encode().unwrap().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();
        if let ciborium::Value::Array(ref mut items) = val {
            items[12] = ciborium::Value::Integer(50.into()); // below 100mm floor
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(matches!(
            WorldConfigV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::SensorResolutionBelowMinimum)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_wrong_field_type_for_backend_id_rejected() {
        let c = sample_config();
        let bytes = c.encode().unwrap().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();
        if let ciborium::Value::Array(ref mut items) = val {
            items[7] = ciborium::Value::Integer(42.into()); // backend_id should be tstr
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(matches!(
            WorldConfigV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_wrong_field_type_for_float_rejected() {
        let o = sample_observation();
        let bytes = o.encode().unwrap().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();
        if let ciborium::Value::Array(ref mut items) = val {
            items[5] = ciborium::Value::Text("not_a_float".to_owned()); // pos_x should be float
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(matches!(
            WorldObservationV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::WrongFieldType)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_payload_too_large_for_sensor_rejected() {
        let o = sample_observation();
        let bytes = o.encode().unwrap().as_slice().to_vec();
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();
        if let ciborium::Value::Array(ref mut items) = val {
            items[19] = ciborium::Value::Bytes(vec![0u8; MAX_SENSOR_VALUE_BYTES + 1]);
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(matches!(
            WorldObservationV1::decode(&CanonicalBytes::from_vec(buf)),
            Err(WorldCodecError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_driver_emits_config_on_first_step() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![], backend, sample_config());
        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
        // First step: config draft only (no bodies)
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_CONFIG_V1);
        // Second step: no config, no bodies
        let out2 = driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert_eq!(out2.drafts.len(), 0);
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
        let mut val: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();
        if let ciborium::Value::Array(ref mut items) = val {
            items[1] = ciborium::Value::Integer(99_i64.into());
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        buf
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_observation_v1_wrong_version_rejected() {
        let o = sample_observation();
        let flipped = flip_version(o.encode().unwrap().as_slice());
        assert!(matches!(
            WorldObservationV1::decode(&CanonicalBytes::from_vec(flipped)),
            Err(WorldCodecError::WrongVersion)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_action_v1_wrong_version_rejected() {
        let a = sample_action();
        let flipped = flip_version(a.encode().unwrap().as_slice());
        assert!(matches!(
            WorldActionV1::decode(&CanonicalBytes::from_vec(flipped)),
            Err(WorldCodecError::WrongVersion)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_config_v1_wrong_version_rejected() {
        let c = sample_config();
        let flipped = flip_version(c.encode().unwrap().as_slice());
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

        assert_eq!(cap.owned_event_types.len(), 2);
        assert_eq!(cap.owned_event_types[0].as_str(), EVENT_TYPE_OBSERVATION);
        assert_eq!(cap.owned_event_types[1].as_str(), EVENT_TYPE_ACTION);
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
        let mut backend = SimpleKinematicBackend::new();
        let entity = EntityId::new();
        let bodies = vec![Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 2.0,
        }];

        let observations = backend.step(&bodies);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].entity_id, entity);
        assert!((observations[0].x - 1.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn simple_kinematic_backend_step_multiple_bodies() {
        let mut backend = SimpleKinematicBackend::new();
        let entity1 = EntityId::new();
        let entity2 = EntityId::new();
        let bodies = vec![
            Body {
                entity_id: entity1,
                x: 0.0,
                y: 0.0,
                vx: 1.0,
                vy: 0.0,
            },
            Body {
                entity_id: entity2,
                x: 10.0,
                y: 10.0,
                vx: -1.0,
                vy: -1.0,
            },
        ];

        let observations = backend.step(&bodies);
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
            pos_core::Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("fixture origin is valid"),
            [23; 32],
            10_000.0,
        )
        .expect("fixture origin is valid");
        let transform = pos_core::WorldTransformV1::new(&capability, origin)
            .expect("fixture transform is valid");
        let position = transform
            .forward(
                &capability,
                pos_core::Wgs84PositionV1::new(35.001, -119.999, 120.0)
                    .expect("fixture position is valid"),
            )
            .expect("fixture position is in range");
        let body = WorldCoordinateBody::new(EntityId::new(), position, 1.5, -2.0, 0.25);
        assert!((body.position().east_metres() - position.east_metres()).abs() < f64::EPSILON);
        assert!((body.position().north_metres() - position.north_metres()).abs() < f64::EPSILON);
        assert!((body.position().up_metres() - position.up_metres()).abs() < f64::EPSILON);

        let mut backend = SimpleKinematicBackend::new();
        let observations = backend
            .step_coordinates(&[body])
            .expect("named coordinate step is finite");

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
            pos_core::Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("fixture is valid"),
            [26; 32],
            10_000.0,
        )
        .expect("fixture origin is valid");
        let transform = pos_core::WorldTransformV1::new(&capability, origin)
            .expect("fixture transform is valid");
        let position = transform
            .forward(
                &capability,
                pos_core::Wgs84PositionV1::new(35.001, -119.999, 120.0)
                    .expect("fixture position is valid"),
            )
            .expect("fixture position is in range");
        let body = WorldCoordinateBody::new(EntityId::new(), position, f64::INFINITY, 0.0, 0.0);
        let mut backend = SimpleKinematicBackend::new();

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
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 1.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend, sample_config());

        // First step: config (index 0) + observation (index 1).
        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert_eq!(out.drafts.len(), 2);
        assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_CONFIG_V1);
        assert_eq!(out.drafts[1].event_type.as_str(), EVENT_TYPE_OBSERVATION_V1);
        // Second step: observation only.
        let out2 = driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert_eq!(out2.drafts.len(), 1);
        assert_eq!(
            out2.drafts[0].event_type.as_str(),
            EVENT_TYPE_OBSERVATION_V1
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_step_produces_decodable_v1_payload() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 5.0,
            y: 10.0,
            vx: 2.0,
            vy: 3.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend, sample_config());

        // First step: drafts[0]=config, drafts[1]=observation.
        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert_eq!(out.drafts.len(), 2);
        let obs = WorldObservationV1::decode(&out.drafts[1].payload).unwrap();
        // Positions are quantized to sensor_min_resolution_mm (100mm = 0.1m).
        let expected_x = ((7.0_f32 / 0.1).round() * 0.1) as f32;
        let expected_y = ((13.0_f32 / 0.1).round() * 0.1) as f32;
        assert!((obs.pos_x - expected_x).abs() < 0.001);
        assert!((obs.pos_y - expected_y).abs() < 0.001);
        assert_eq!(obs.tick, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_updates_body_positions() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 1.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend, sample_config());

        driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert!((driver.entities[0].x - 1.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 1.0).abs() < f64::EPSILON);

        driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert!((driver.entities[0].x - 2.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 2.0).abs() < f64::EPSILON);
    }

    struct UnknownEntityBackend;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl WorldBackend for UnknownEntityBackend {
        fn name(&self) -> &'static str {
            "unknown-entity"
        }

        fn step(&mut self, _bodies: &[Body]) -> Vec<WorldObservation> {
            vec![WorldObservation {
                entity_id: EntityId::new(),
                x: 9.0,
                y: 9.0,
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

        fn step(&mut self, bodies: &[Body]) -> Vec<WorldObservation> {
            let mut out: Vec<WorldObservation> = bodies
                .iter()
                .map(|body| WorldObservation {
                    entity_id: body.entity_id,
                    x: body.x + body.vx,
                    y: body.y + body.vy,
                })
                .collect();
            out.push(WorldObservation {
                entity_id: self.extra,
                x: 0.0,
                y: 0.0,
            });
            out
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_ignores_observations_for_unknown_entities() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let known = EntityId::new();
        let body = Body {
            entity_id: known,
            x: 1.0,
            y: 2.0,
            vx: 0.0,
            vy: 0.0,
        };
        let mut driver =
            WorldDriver::new(vec![body], Box::new(UnknownEntityBackend), sample_config());
        assert_eq!(UnknownEntityBackend.name(), "unknown-entity");
        // First step: config + observation for the unknown entity (backend returns unknown id,
        // so body state is unchanged, but an observation draft is still emitted for it).
        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert_eq!(out.drafts.len(), 2); // config + one observation from unknown backend
        assert!((driver.entities[0].x - 1.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_updates_known_and_skips_unknown_in_same_step() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let known = EntityId::new();
        let unknown = EntityId::new();
        let body = Body {
            entity_id: known,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 2.0,
        };
        let mut driver = WorldDriver::new(
            vec![body],
            Box::new(MixedEntityBackend { extra: unknown }),
            sample_config(),
        );
        assert_eq!(MixedEntityBackend { extra: unknown }.name(), "mixed-entity");
        driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert!((driver.entities[0].x - 1.0).abs() < f64::EPSILON);
        assert!((driver.entities[0].y - 2.0).abs() < f64::EPSILON);
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
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn body_partial_eq() {
        let entity = EntityId::new();
        let b1 = Body {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
            vx: 0.0,
            vy: 0.0,
        };
        let b2 = Body {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
            vx: 0.0,
            vy: 0.0,
        };
        let b3 = Body {
            entity_id: entity,
            x: 3.0,
            y: 4.0,
            vx: 0.0,
            vy: 0.0,
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
        };
        let o2 = WorldObservation {
            entity_id: entity,
            x: 1.0,
            y: 2.0,
        };
        let o3 = WorldObservation {
            entity_id: entity,
            x: 3.0,
            y: 4.0,
        };
        assert_eq!(o1, o2);
        assert_ne!(o1, o3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_empty_bodies_produces_no_events() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![], backend, sample_config());

        // First step: config event only (no bodies → no observations).
        let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert_eq!(out.drafts.len(), 1);
        assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_CONFIG_V1);
        // Second step: no config, no bodies → no events.
        let out2 = driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert_eq!(out2.drafts.len(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backend_step_with_zero_velocity() {
        let mut backend = SimpleKinematicBackend::new();
        let entity = EntityId::new();
        let bodies = vec![Body {
            entity_id: entity,
            x: 5.0,
            y: 7.0,
            vx: 0.0,
            vy: 0.0,
        }];

        let observations = backend.step(&bodies);
        assert_eq!(observations.len(), 1);
        assert!((observations[0].x - 5.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backend_step_with_negative_velocity() {
        let mut backend = SimpleKinematicBackend::new();
        let entity = EntityId::new();
        let bodies = vec![Body {
            entity_id: entity,
            x: 10.0,
            y: 10.0,
            vx: -2.0,
            vy: -3.0,
        }];

        let observations = backend.step(&bodies);
        assert_eq!(observations.len(), 1);
        assert!((observations[0].x - 8.0).abs() < f64::EPSILON);
        assert!((observations[0].y - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_tick_increments() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 1.0,
        };
        let backend = Box::new(SimpleKinematicBackend::new());
        let mut driver = WorldDriver::new(vec![body], backend, sample_config());

        assert_eq!(driver.tick, 0);
        driver.step(tl.id(), ObservationView::empty()).unwrap();
        assert_eq!(driver.tick, 1);
        driver.step(tl.id(), ObservationView::empty()).unwrap();
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
                vx: 1.5,
                vy: -0.5,
            };

            // With resolution_mm=100 (0.1m), both 1.5 and -0.5 are exact multiples.
            let expected_pos_x = ((1.5_f32 / 0.1).round() * 0.1) as f32;
            let expected_pos_y = ((-0.5_f32 / 0.1).round() * 0.1) as f32;

            // First independent run.
            let mut store1 = open_store(StoreConfig::Memory).unwrap();
            let tl1 = store1.create_timeline("fixture-1").unwrap();
            let mut driver1 = WorldDriver::new(
                vec![body.clone()],
                Box::new(SimpleKinematicBackend::new()),
                sample_config(),
            );
            let out1 = driver1.step(tl1.id(), ObservationView::empty()).unwrap();
            // drafts[0]=config, drafts[1]=observation
            assert_eq!(out1.drafts.len(), 2);
            let obs1 = WorldObservationV1::decode(&out1.drafts[1].payload).unwrap();
            assert!((obs1.pos_x - expected_pos_x).abs() < 0.001);
            assert!((obs1.pos_y - expected_pos_y).abs() < 0.001);

            // Second independent run — same input must produce same output (determinism).
            let mut store2 = open_store(StoreConfig::Memory).unwrap();
            let tl2 = store2.create_timeline("fixture-2").unwrap();
            let mut driver2 = WorldDriver::new(
                vec![body],
                Box::new(SimpleKinematicBackend::new()),
                sample_config(),
            );
            let out2 = driver2.step(tl2.id(), ObservationView::empty()).unwrap();
            assert_eq!(out2.drafts.len(), 2);
            let obs2 = WorldObservationV1::decode(&out2.drafts[1].payload).unwrap();
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
            let mut store = open_store(StoreConfig::Memory).unwrap();
            let tl = store.create_timeline("sensor-kind-test").unwrap();
            let entity = EntityId::new();
            let body = Body {
                entity_id: entity,
                x: 0.0,
                y: 0.0,
                vx: 1.0,
                vy: 0.0,
            };
            let mut driver = WorldDriver::new(
                vec![body],
                Box::new(SimpleKinematicBackend::new()),
                sample_config(),
            );
            let out = driver.step(tl.id(), ObservationView::empty()).unwrap();
            // drafts[0]=config, drafts[1]=observation
            assert_eq!(out.drafts.len(), 2);
            let obs = WorldObservationV1::decode(&out.drafts[1].payload).unwrap();
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
            payload: action.encode().unwrap(),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    fn encode_vel_params(vx: f32, vy: f32) -> Vec<u8> {
        cbor_encode(&ciborium::Value::Array(vec![
            cbor_f32(vx).unwrap(),
            cbor_f32(vy).unwrap(),
        ]))
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_applies_impulse_action_to_body() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 0.0,
        };
        let mut driver = WorldDriver::new(
            vec![body],
            Box::new(SimpleKinematicBackend::new()),
            sample_config(),
        );

        // Impulse (+0.5, +2.0): resulting vx=1.5, vy=2.0 → backend step: x=1.5, y=2.0.
        let action = WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: entity,
            action_kind: ActionKindV1::Impulse,
            params_cbor: encode_vel_params(0.5, 2.0),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let events = vec![make_action_event_from(entity, &action)];
        let out = driver
            .step(tl.id(), ObservationView::from_events(&events))
            .unwrap();
        let obs_draft = out
            .drafts
            .iter()
            .find(|d| d.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .unwrap();
        let obs = WorldObservationV1::decode(&obs_draft.payload).unwrap();
        // 100 mm quantization; 1.5 m and 2.0 m are exact multiples of 0.1 m.
        assert!((obs.pos_x - 1.5_f32).abs() < 0.15);
        assert!((obs.pos_y - 2.0_f32).abs() < 0.15);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_applies_target_velocity_action() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        // High initial velocity; TargetVelocity must override it entirely.
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 10.0,
            vy: 10.0,
        };
        let mut driver = WorldDriver::new(
            vec![body],
            Box::new(SimpleKinematicBackend::new()),
            sample_config(),
        );

        // TargetVelocity (2.0, 0.5) → backend step: x=2.0, y=0.5.
        let action = WorldActionV1 {
            actor_entity_id: EntityId::new(),
            body_entity_id: entity,
            action_kind: ActionKindV1::TargetVelocity,
            params_cbor: encode_vel_params(2.0, 0.5),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let events = vec![make_action_event_from(entity, &action)];
        let out = driver
            .step(tl.id(), ObservationView::from_events(&events))
            .unwrap();
        let obs_draft = out
            .drafts
            .iter()
            .find(|d| d.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .unwrap();
        let obs = WorldObservationV1::decode(&obs_draft.payload).unwrap();
        assert!((obs.pos_x - 2.0_f32).abs() < 0.15);
        assert!((obs.pos_y - 0.5_f32).abs() < 0.15);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_ignores_malformed_action_payload() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();
        let body = Body {
            entity_id: entity,
            x: 0.0,
            y: 0.0,
            vx: 1.0,
            vy: 1.0,
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
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        let events = vec![bad_event];
        // Must not panic; body moves with original velocity (1,1) → pos (1,1).
        let out = driver
            .step(tl.id(), ObservationView::from_events(&events))
            .unwrap();
        let obs_draft = out
            .drafts
            .iter()
            .find(|d| d.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .unwrap();
        let obs = WorldObservationV1::decode(&obs_draft.payload).unwrap();
        assert!((obs.pos_x - 1.0_f32).abs() < 0.15);
        assert!((obs.pos_y - 1.0_f32).abs() < 0.15);
    }
}
