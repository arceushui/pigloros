//! Shared deterministic-CBOR helpers for the ADR-064 counterfactual codecs.
//!
//! Every counterfactual record is one definite-length CBOR array whose first
//! two items are a text magic and an unsigned schema version. This module owns
//! the parts every such codec repeats: the size bound, structural preflight,
//! canonical round-trip check, value builders for encoding, and a
//! [`FieldReader`] for decoding.
//!
//! Helpers return the closed [`WireError`]; each contract maps it onto its own
//! public error once, through one `const fn` with one arm per variant.
//!
//! [`FieldReader`] records the first field error and returns a fallback for
//! every later read, so a decoder reads all fields straight-line and checks
//! the outcome once with [`FieldReader::finish`]. A wrong-typed field therefore
//! funnels through the reader's single error path instead of adding one
//! early-return `?` region per field.
//!
//! Adopting this module in a sibling codec (dependency, checkpoint, result,
//! frontier artifacts, plan):
//!
//! 1. Replace the local `encode_value`, `decode_value`, preflight mapping,
//!    `array`, `text_value`, `uint_value`, `u32` and `fixed_bytes` helpers with
//!    [`encode_value`], [`decode_canonical`] plus a `const` [`CborLimits`], and
//!    the [`FieldReader`] `read_*` methods.
//! 2. Decode with [`FieldReader::with_header`] for the record and
//!    [`FieldReader::new`] for nested fixed-length arrays, then return
//!    `reader.finish().map(|()| record)`.
//! 3. Read closed enum codes with [`FieldReader::read_enum`] over a `const`
//!    code table, and embedded node coordinates with
//!    [`FieldReader::read_node`]. Optional fields and variable-length lists
//!    are added here as `read_*` methods over [`FieldReader::read_with`]; any
//!    helper added here must be exercised by the contract that introduces it,
//!    because unused helpers fail the build and untested branches fail the
//!    region gate.

use crate::DependencyNodeV1;
use ciborium::value::Value;
use std::io::Cursor;

/// Closed codec failures shared by the counterfactual contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WireError {
    /// Malformed, noncanonical, or wrongly typed CBOR.
    InvalidEncoding,
    /// An encoded size, nesting depth, item count, or integer exceeds its bound.
    FieldOutOfBounds,
    /// The record magic or schema version is not the expected one.
    UnsupportedVersion,
    /// A well-typed enum code lies outside its closed code table.
    UnknownEnum,
}

/// Structural bounds checked before a record is decoded.
#[derive(Clone, Copy, Debug)]
pub(super) struct CborLimits {
    /// Maximum encoded record size in bytes.
    pub(super) maximum_bytes: usize,
    /// Maximum array nesting depth below the top-level record.
    pub(super) maximum_depth: u8,
    /// Maximum item count of any array.
    pub(super) maximum_items: u64,
    /// Whether `false`, `true`, and `null` are admitted.
    pub(super) allow_simple_values: bool,
}

/// Encode one value as deterministic CBOR.
pub(super) fn encode_value<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, WireError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .or(Err(WireError::InvalidEncoding))
}

/// Decode exact canonical CBOR bounded by `limits`.
///
/// Oversized input fails with [`WireError::FieldOutOfBounds`] before any
/// parsing; input that parses but does not re-encode to identical bytes fails
/// with [`WireError::InvalidEncoding`].
pub(super) fn decode_canonical(bytes: &[u8], limits: CborLimits) -> Result<Value, WireError> {
    if bytes.len() > limits.maximum_bytes {
        return Err(WireError::FieldOutOfBounds);
    }
    crate::preflight_array_cbor(
        bytes,
        limits.maximum_depth,
        limits.maximum_items,
        limits.allow_simple_values,
    )
    .map_err(preflight_error)
    .and_then(|()| {
        ciborium::from_reader::<Value, _>(Cursor::new(bytes)).or(Err(WireError::InvalidEncoding))
    })
    .and_then(|value| {
        encode_value(&value).and_then(|canonical| {
            if canonical == bytes {
                Ok(value)
            } else {
                Err(WireError::InvalidEncoding)
            }
        })
    })
}

const fn preflight_error(error: crate::CborPreflightError) -> WireError {
    match error {
        crate::CborPreflightError::InvalidEncoding => WireError::InvalidEncoding,
        crate::CborPreflightError::FieldOutOfBounds => WireError::FieldOutOfBounds,
    }
}

/// Whether `bytes` holds any nonzero byte.
///
/// Counterfactual records reserve the all-zero value of every fixed-width
/// identity and digest as "absent", so each contract rejects it through this
/// one predicate.
pub(super) fn nonzero<const LENGTH: usize>(bytes: &[u8; LENGTH]) -> bool {
    *bytes != [0; LENGTH]
}

/// Unsigned integer value for encoding.
pub(super) fn uint_value(value: u64) -> Value {
    Value::Integer(value.into())
}

/// Text value for encoding.
pub(super) fn text_value(value: &str) -> Value {
    Value::Text(value.to_owned())
}

/// Byte-string value for encoding.
pub(super) fn bytes_value(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

/// Six-field `[tick, scheduler_position, owner_id, output_ordinal,
/// schema_id, artifact_digest]` array of one dependency-graph node.
///
/// This is the single node encoding shared by every counterfactual record
/// that embeds a node coordinate.
pub(super) fn node_value(node: &DependencyNodeV1) -> Value {
    Value::Array(vec![
        uint_value(node.tick),
        uint_value(node.scheduler_position.into()),
        text_value(&node.owner_id),
        uint_value(node.output_ordinal.into()),
        uint_value(node.schema_id.into()),
        bytes_value(&node.artifact_digest),
    ])
}

/// Sequential reader over the fields of one fixed-length CBOR array.
///
/// The first failure is kept; every read after it still advances and returns
/// its fallback, so callers check the outcome once with [`Self::finish`].
pub(super) struct FieldReader<'a> {
    fields: &'a [Value],
    next: usize,
    error: Option<WireError>,
}

impl<'a> FieldReader<'a> {
    /// Read the fields of `value`, which must be an array of exactly `length`
    /// items; any other value records [`WireError::InvalidEncoding`].
    pub(super) fn new(value: &'a Value, length: usize) -> Self {
        match value {
            Value::Array(fields) if fields.len() == length => Self {
                fields,
                next: 0,
                error: None,
            },
            _ => Self {
                fields: &[],
                next: 0,
                error: Some(WireError::InvalidEncoding),
            },
        }
    }

    /// Read a record array whose first two fields are `magic` and `version`.
    ///
    /// The header is read before the field count is checked, so a record of
    /// another magic or version is reported as such whatever its length:
    /// a non-array value, a missing or wrongly typed header field records
    /// [`WireError::InvalidEncoding`]; a well-typed but different magic or
    /// version records [`WireError::UnsupportedVersion`]; only a supported
    /// header with other than `length` fields records
    /// [`WireError::InvalidEncoding`].
    pub(super) fn with_header(value: &'a Value, length: usize, magic: &str, version: u64) -> Self {
        let count = match value {
            Value::Array(fields) => fields.len(),
            _ => length,
        };
        let mut reader = Self::new(value, count);
        let read_magic = reader.read_text();
        let read_version = reader.read_u64();
        if reader.error.is_none() {
            if read_magic != magic || read_version != version {
                reader.error = Some(WireError::UnsupportedVersion);
            } else if count != length {
                reader.error = Some(WireError::InvalidEncoding);
            }
        }
        reader
    }

    /// Decode the next field with `decode`, or return `fallback` once any
    /// field has failed or this one fails.
    pub(super) fn read_with<T>(
        &mut self,
        decode: impl FnOnce(&Value) -> Result<T, WireError>,
        fallback: T,
    ) -> T {
        let decoded = self
            .fields
            .get(self.next)
            .ok_or(WireError::InvalidEncoding)
            .and_then(decode);
        self.next += 1;
        decoded.unwrap_or_else(|error| {
            self.error = self.error.or(Some(error));
            fallback
        })
    }

    /// Read a text field.
    pub(super) fn read_text(&mut self) -> String {
        self.read_with(text_field, String::new())
    }

    /// Read an unsigned integer field.
    pub(super) fn read_u64(&mut self) -> u64 {
        self.read_with(u64_field, 0)
    }

    /// Read an unsigned integer field; values above `u32::MAX` record
    /// [`WireError::FieldOutOfBounds`].
    pub(super) fn read_u32(&mut self) -> u32 {
        self.read_with(u32_field, 0)
    }

    /// Read a byte-string field of exactly `LENGTH` bytes.
    pub(super) fn read_bytes<const LENGTH: usize>(&mut self) -> [u8; LENGTH] {
        self.read_with(fixed_bytes_field::<LENGTH>, [0; LENGTH])
    }

    /// Read a closed enum whose wire code indexes `codes`; a non-integer
    /// records [`WireError::InvalidEncoding`] and a code outside the table
    /// records [`WireError::UnknownEnum`].
    pub(super) fn read_enum<T: Copy>(&mut self, codes: &[T], fallback: T) -> T {
        self.read_with(
            |value| u64_field(value).and_then(|code| enum_code(code, codes)),
            fallback,
        )
    }

    /// Read a field that is either `null` or a byte string of exactly
    /// `LENGTH` bytes.
    pub(super) fn read_optional_bytes<const LENGTH: usize>(&mut self) -> Option<[u8; LENGTH]> {
        self.read_with(optional_bytes_field::<LENGTH>, None)
    }

    /// Read a variable-length array field, decoding every item with `decode`.
    ///
    /// Item-count bounds are enforced by the [`CborLimits`] preflight and by
    /// the contract's validation, not here.
    pub(super) fn read_array<T>(&mut self, decode: fn(&Value) -> Result<T, WireError>) -> Vec<T> {
        self.read_with(|value| array_values(value, decode), Vec::new())
    }

    /// Read a node coordinate encoded by [`node_value`].
    pub(super) fn read_node(&mut self) -> DependencyNodeV1 {
        self.read_with(
            node_field,
            DependencyNodeV1 {
                tick: 0,
                scheduler_position: 0,
                owner_id: String::new(),
                output_ordinal: 0,
                schema_id: 0,
                artifact_digest: [0; 32],
            },
        )
    }

    /// Return the first recorded failure, if any.
    pub(super) fn finish(self) -> Result<(), WireError> {
        self.error.map_or(Ok(()), Err)
    }
}

fn text_field(value: &Value) -> Result<String, WireError> {
    match value {
        Value::Text(text) => Ok(text.clone()),
        _ => Err(WireError::InvalidEncoding),
    }
}

fn u64_field(value: &Value) -> Result<u64, WireError> {
    match value {
        Value::Integer(integer) => u64::try_from(*integer).or(Err(WireError::InvalidEncoding)),
        _ => Err(WireError::InvalidEncoding),
    }
}

fn u32_field(value: &Value) -> Result<u32, WireError> {
    u64_field(value).and_then(|integer| u32::try_from(integer).or(Err(WireError::FieldOutOfBounds)))
}

fn fixed_bytes_field<const LENGTH: usize>(value: &Value) -> Result<[u8; LENGTH], WireError> {
    match value {
        Value::Bytes(bytes) => {
            <[u8; LENGTH]>::try_from(bytes.as_slice()).or(Err(WireError::InvalidEncoding))
        }
        _ => Err(WireError::InvalidEncoding),
    }
}

fn enum_code<T: Copy>(code: u64, codes: &[T]) -> Result<T, WireError> {
    usize::try_from(code)
        .ok()
        .and_then(|index| codes.get(index))
        .copied()
        .ok_or(WireError::UnknownEnum)
}

fn optional_bytes_field<const LENGTH: usize>(
    value: &Value,
) -> Result<Option<[u8; LENGTH]>, WireError> {
    match value {
        Value::Null => Ok(None),
        value => fixed_bytes_field::<LENGTH>(value).map(Some),
    }
}

fn array_values<T>(
    value: &Value,
    decode: fn(&Value) -> Result<T, WireError>,
) -> Result<Vec<T>, WireError> {
    match value {
        Value::Array(values) => values.iter().map(decode).collect(),
        _ => Err(WireError::InvalidEncoding),
    }
}

fn node_field(value: &Value) -> Result<DependencyNodeV1, WireError> {
    let mut fields = FieldReader::new(value, 6);
    let tick = fields.read_u64();
    let scheduler_position = fields.read_u32();
    let owner_id = fields.read_text();
    let output_ordinal = fields.read_u32();
    let schema_id = fields.read_u32();
    let artifact_digest = fields.read_bytes::<32>();
    fields.finish().map(|()| DependencyNodeV1 {
        tick,
        scheduler_position,
        owner_id,
        output_ordinal,
        schema_id,
        artifact_digest,
    })
}
