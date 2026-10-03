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
//!    [`FieldReader::new`] or [`FieldReader::read_nested`] for nested
//!    fixed-length arrays, then return `reader.finish().map(|()| record)`, or
//!    use [`FieldReader::finish_at`] to name the failing field.
//! 3. Read closed enum codes with [`FieldReader::read_enum`] over a `const`
//!    code table, optional fields with the `read_optional*` methods,
//!    variable-length lists with [`FieldReader::read_array`], and embedded
//!    node coordinates with [`FieldReader::read_node`].
//! 4. Any helper added here must be exercised by the contract that introduces
//!    it, because unused helpers fail the build and untested branches fail the
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

/// Number of fields in one node coordinate encoded by [`node_value`].
const NODE_FIELD_COUNT: usize = 6;

/// Sequential reader over the fields of one fixed-length CBOR array.
///
/// The first failure is kept; every read after it still advances and returns
/// its fallback, so callers check the outcome once with [`Self::finish`].
///
/// Every read also advances a flat field slot, so [`Self::finish_at`] can name
/// the first failing field. Slot 0 is the array itself and slot 1 its first
/// field; a [`Self::read_nested`] array takes one slot for itself followed by
/// one per nested field, so a record's slot layout is fixed by its schema.
pub(super) struct FieldReader<'a> {
    fields: &'a [Value],
    next: usize,
    slot: usize,
    failure: Option<(WireError, usize)>,
}

impl<'a> FieldReader<'a> {
    /// Read the fields of `value`, which must be an array of exactly `length`
    /// items; any other value records [`WireError::InvalidEncoding`].
    pub(super) fn new(value: &'a Value, length: usize) -> Self {
        let fields = exact_array(Some(value), length);
        Self {
            fields: fields.unwrap_or_default(),
            next: 0,
            slot: 1,
            failure: fields.is_none().then_some((WireError::InvalidEncoding, 0)),
        }
    }

    /// Read a record array whose first two fields are `magic` and `version`.
    ///
    /// The header is read before the field count is checked, so a record of
    /// another magic or version is reported as such whatever its length:
    /// a non-array value, a missing or wrongly typed header field records
    /// [`WireError::InvalidEncoding`]; a well-typed but different magic or
    /// version records [`WireError::UnsupportedVersion`] at the magic slot;
    /// only a supported header with other than `length` fields records
    /// [`WireError::InvalidEncoding`] at the array's own slot 0.
    pub(super) fn with_header(value: &'a Value, length: usize, magic: &str, version: u64) -> Self {
        let count = match value {
            Value::Array(fields) => fields.len(),
            _ => length,
        };
        let mut reader = Self::new(value, count);
        let magic_slot = reader.slot;
        let read_magic = reader.read_text();
        let read_version = reader.read_u64();
        if reader.failure.is_none() {
            if read_magic != magic || read_version != version {
                reader.failure = Some((WireError::UnsupportedVersion, magic_slot));
            } else if count != length {
                reader.failure = Some((WireError::InvalidEncoding, 0));
            }
        }
        reader
    }

    /// Read the next field as a nested array of exactly `length` items with
    /// `decode`, which reads the nested fields from the same reader state.
    ///
    /// Any other value records [`WireError::InvalidEncoding`] at the nested
    /// array's own slot.
    pub(super) fn read_nested<T>(
        &mut self,
        length: usize,
        decode: impl FnOnce(&mut Self) -> T,
    ) -> T {
        let parent_fields: &'a [Value] = self.fields;
        let fields = exact_array(parent_fields.get(self.next), length);
        let shape_failure = fields
            .is_none()
            .then_some((WireError::InvalidEncoding, self.slot));
        let mut nested = Self {
            fields: fields.unwrap_or_default(),
            next: 0,
            slot: self.slot + 1,
            failure: self.failure.or(shape_failure),
        };
        let decoded = decode(&mut nested);
        self.next += 1;
        self.slot = nested.slot;
        self.failure = nested.failure;
        decoded
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
        let slot = self.slot;
        self.next += 1;
        self.slot += 1;
        decoded.unwrap_or_else(|error| {
            self.failure = self.failure.or(Some((error, slot)));
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
        self.read_optional(fixed_bytes_field::<LENGTH>)
    }

    /// Read a field that is either `null` or an unsigned integer.
    pub(super) fn read_optional_u64(&mut self) -> Option<u64> {
        self.read_optional(u64_field)
    }

    /// Read a field that is either `null` or a value decoded by `decode`.
    pub(super) fn read_optional<T>(
        &mut self,
        decode: fn(&Value) -> Result<T, WireError>,
    ) -> Option<T> {
        self.read_with(|value| optional_field(value, decode), None)
    }

    /// Read a variable-length array field, decoding every item with `decode`.
    ///
    /// Item-count bounds are enforced by the [`CborLimits`] preflight and by
    /// the contract's validation, not here.
    pub(super) fn read_array<T>(&mut self, decode: fn(&Value) -> Result<T, WireError>) -> Vec<T> {
        self.read_with(|value| array_values(value, decode), Vec::new())
    }

    /// Read a variable-length array of byte strings of exactly `LENGTH`
    /// bytes each.
    pub(super) fn read_bytes_list<const LENGTH: usize>(&mut self) -> Vec<[u8; LENGTH]> {
        self.read_array(fixed_bytes_field::<LENGTH>)
    }

    /// Read a node coordinate encoded by [`node_value`] as a nested array.
    pub(super) fn read_node(&mut self) -> DependencyNodeV1 {
        self.read_nested(NODE_FIELD_COUNT, Self::node_fields)
    }

    /// Read a variable-length array of node coordinates.
    pub(super) fn read_node_list(&mut self) -> Vec<DependencyNodeV1> {
        self.read_array(node_field)
    }

    fn node_fields(&mut self) -> DependencyNodeV1 {
        DependencyNodeV1 {
            tick: self.read_u64(),
            scheduler_position: self.read_u32(),
            owner_id: self.read_text(),
            output_ordinal: self.read_u32(),
            schema_id: self.read_u32(),
            artifact_digest: self.read_bytes(),
        }
    }

    /// Return the first recorded failure, if any.
    pub(super) fn finish(self) -> Result<(), WireError> {
        self.failure.map_or(Ok(()), |(error, _)| Err(error))
    }

    /// Return the first recorded failure together with its field slot.
    pub(super) fn finish_at(self) -> Result<(), (WireError, usize)> {
        self.failure.map_or(Ok(()), Err)
    }
}

/// Decode a node coordinate encoded by [`node_value`]; a failure carries its
/// slot, 0 for the array and 1 through 6 for its fields.
pub(super) fn decode_node(value: &Value) -> Result<DependencyNodeV1, (WireError, usize)> {
    let mut fields = FieldReader::new(value, NODE_FIELD_COUNT);
    let node = fields.node_fields();
    fields.finish_at().map(|()| node)
}

const fn exact_array(value: Option<&Value>, length: usize) -> Option<&[Value]> {
    match value {
        Some(Value::Array(fields)) if fields.len() == length => Some(fields.as_slice()),
        _ => None,
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

fn optional_field<T>(
    value: &Value,
    decode: fn(&Value) -> Result<T, WireError>,
) -> Result<Option<T>, WireError> {
    match value {
        Value::Null => Ok(None),
        value => decode(value).map(Some),
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
    decode_node(value).map_err(|(error, _)| error)
}
