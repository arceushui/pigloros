//! Standalone IDP1 input-dependency edges defined by ADR-064.
//!
//! One [`InputDependencyV1`] names exactly one directed edge from a source
//! node to a consumer node. Each node is the exact coordinate
//! `[tick, scheduler_position, owner_id, output_ordinal, schema_id, digest]`.
//! The record binds the closed dependency class, the inclusive Tick range the
//! edge covers, the authorization decision, the classification rule and
//! version that assigned the class, and the provenance of the edge.
//!
//! The wire form is the exact nine-field deterministic-CBOR array of magic
//! `IDP1`, version `1`, consumer node, source node, class code,
//! `[first_tick, last_tick]`, authorization digest, `[rule_id, rule_version]`,
//! and provenance digest. Graph completeness, reachability, and frontier
//! derivation are owned by later ADR-064 contracts and are not decided here.

use crate::{domain_digest, DependencyClassV1, DependencyNodeV1};
use ciborium::value::Value;
use std::cmp::Ordering;

/// Magic for the standalone input-dependency record.
pub const INPUT_DEPENDENCY_MAGIC_V1: &str = "IDP1";
/// Maximum encoded size of an IDP1 input-dependency record.
pub const MAX_INPUT_DEPENDENCY_BYTES_V1: usize = 16 * 1024;

const FIELD_COUNT: usize = 9;
const NODE_FIELD_COUNT: usize = 6;
const MAX_OWNER_ID_BYTES: usize = 128;
const MAX_RULE_ID_BYTES: usize = 128;
const MAX_NESTING_DEPTH: u8 = 2;
const DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.InputDependency.v1";

/// Closed safe errors exposed by the IDP1 contract.
///
/// The variants are the IDP1 subset of the closed ADR-064 error set; they
/// carry no payload, subject data, or coordinate text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputDependencyContractErrorV1 {
    /// The bytes are malformed, noncanonical, or contain a forbidden CBOR type.
    InvalidEncoding,
    /// The record magic or schema version is not supported.
    UnsupportedVersion,
    /// A required value or the encoded record exceeds its specified bound.
    FieldOutOfBounds,
    /// The dependency-class code is outside the closed class set.
    UnknownEnum,
    /// A source does not precede its consumer, or an edge list is out of order.
    NonCanonicalOrder,
    /// An edge list repeats one canonical edge identity.
    DuplicateIdentity,
}

impl std::fmt::Display for InputDependencyContractErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid IDP1 input-dependency encoding",
            Self::UnsupportedVersion => "unsupported IDP1 input-dependency version",
            Self::FieldOutOfBounds => "IDP1 input-dependency field is out of bounds",
            Self::UnknownEnum => "IDP1 input-dependency class is unknown",
            Self::NonCanonicalOrder => "IDP1 input-dependency coordinates are not canonical",
            Self::DuplicateIdentity => "IDP1 input-dependency edge identity is duplicated",
        })
    }
}

impl std::error::Error for InputDependencyContractErrorV1 {}

/// Inclusive Tick range covered by one dependency edge.
///
/// The range must contain both endpoints: `first_tick <= source.tick` and
/// `consumer.tick <= last_tick`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DependencyTickRangeV1 {
    pub first_tick: u64,
    pub last_tick: u64,
}

/// Exact classification rule identity that assigned the dependency class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyClassificationRuleV1 {
    /// Bounded lowercase rule identifier.
    pub rule_id: String,
    /// Nonzero rule version; new classification semantics need a new version.
    pub rule_version: u32,
}

/// One closed IDP1 dependency edge from a source node to a consumer node.
///
/// Both coordinates need a 1–128 byte UTF-8 owner, a nonzero schema, and a
/// nonzero artifact digest, and the source must strictly precede the
/// consumer in `(tick, scheduler_position, owner_id bytes, output_ordinal)`
/// order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputDependencyV1 {
    pub consumer: DependencyNodeV1,
    pub source: DependencyNodeV1,
    pub dependency_class: DependencyClassV1,
    pub tick_range: DependencyTickRangeV1,
    pub authorization_digest: [u8; 32],
    pub classification_rule: DependencyClassificationRuleV1,
    pub provenance_digest: [u8; 32],
}

impl InputDependencyV1 {
    /// Convert one proof-local evidence edge into a validated IDP1 record.
    ///
    /// The proof evidence carries no classification rule or Tick range, so
    /// the caller names the rule explicitly and the range is the exact span
    /// `[source.tick, consumer.tick]`. Nothing else is invented.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the converted edge is invalid, for
    /// example a zero-digest placeholder source accepted by proof evidence.
    pub fn from_proof_evidence_v1(
        evidence: &crate::InputDependencyV1,
        classification_rule: DependencyClassificationRuleV1,
    ) -> Result<Self, InputDependencyContractErrorV1> {
        let dependency = Self {
            consumer: evidence.consumer.clone(),
            source: evidence.source.clone(),
            dependency_class: evidence.dependency_class,
            tick_range: DependencyTickRangeV1 {
                first_tick: evidence.source.tick,
                last_tick: evidence.consumer.tick,
            },
            authorization_digest: evidence.authorization_digest,
            classification_rule,
            provenance_digest: evidence.provenance_digest,
        };
        dependency.validate().map(|()| dependency)
    }

    /// Validate field bounds, nonzero digests, and coordinate order.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field or coordinate is invalid.
    pub fn validate(&self) -> Result<(), InputDependencyContractErrorV1> {
        if !valid_node(&self.consumer)
            || !valid_node(&self.source)
            || self.tick_range.first_tick > self.source.tick
            || self.tick_range.last_tick < self.consumer.tick
            || !nonzero(&self.authorization_digest)
            || !valid_rule(&self.classification_rule)
            || !nonzero(&self.provenance_digest)
        {
            Err(InputDependencyContractErrorV1::FieldOutOfBounds)
        } else if coordinate(&self.source) < coordinate(&self.consumer) {
            Ok(())
        } else {
            Err(InputDependencyContractErrorV1::NonCanonicalOrder)
        }
    }

    /// Encode this edge as an exact deterministic-CBOR IDP1 array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, InputDependencyContractErrorV1> {
        self.validate()
            .and_then(|()| encode_value(&encode_dependency(self)))
    }

    /// Decode and validate exact canonical IDP1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, oversized, or
    /// invalid IDP1 records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, InputDependencyContractErrorV1> {
        if bytes.len() > MAX_INPUT_DEPENDENCY_BYTES_V1 {
            Err(InputDependencyContractErrorV1::FieldOutOfBounds)
        } else {
            decode_value(bytes)
                .and_then(|value| decode_dependency(&value))
                .and_then(|dependency| dependency.validate().map(|()| dependency))
        }
    }

    /// Compute the domain-separated BLAKE3 digest of the canonical IDP1 bytes
    /// using `PiglorOS.InputDependency.v1\0`.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the edge is invalid.
    pub fn digest(&self) -> Result<[u8; 32], InputDependencyContractErrorV1> {
        self.to_canonical_cbor()
            .map(|bytes| domain_digest(DIGEST_DOMAIN_V1, &bytes))
    }
}

/// Validate every edge and the canonical edge-list order.
///
/// Edges sort by `(consumer tick, consumer scheduler position, consumer owner
/// bytes, consumer output ordinal, source digest)` with no repeated key.
///
/// # Errors
///
/// Returns the first member's validation error, [`DuplicateIdentity`] for a
/// repeated key, or [`NonCanonicalOrder`] for a descending pair.
///
/// [`DuplicateIdentity`]: InputDependencyContractErrorV1::DuplicateIdentity
/// [`NonCanonicalOrder`]: InputDependencyContractErrorV1::NonCanonicalOrder
pub fn validate_input_dependency_order_v1(
    dependencies: &[InputDependencyV1],
) -> Result<(), InputDependencyContractErrorV1> {
    dependencies
        .iter()
        .try_for_each(InputDependencyV1::validate)
        .and_then(|()| {
            dependencies.windows(2).try_for_each(|pair| {
                match edge_order_key(&pair[0]).cmp(&edge_order_key(&pair[1])) {
                    Ordering::Less => Ok(()),
                    Ordering::Equal => Err(InputDependencyContractErrorV1::DuplicateIdentity),
                    Ordering::Greater => Err(InputDependencyContractErrorV1::NonCanonicalOrder),
                }
            })
        })
}

const fn edge_order_key(dependency: &InputDependencyV1) -> (u64, u32, &str, u32, &[u8; 32]) {
    (
        dependency.consumer.tick,
        dependency.consumer.scheduler_position,
        dependency.consumer.owner_id.as_str(),
        dependency.consumer.output_ordinal,
        &dependency.source.artifact_digest,
    )
}

const fn coordinate(node: &DependencyNodeV1) -> (u64, u32, &str, u32) {
    (
        node.tick,
        node.scheduler_position,
        node.owner_id.as_str(),
        node.output_ordinal,
    )
}

fn valid_node(node: &DependencyNodeV1) -> bool {
    valid_owner_id(&node.owner_id) && node.schema_id != 0 && nonzero(&node.artifact_digest)
}

const fn valid_owner_id(owner_id: &str) -> bool {
    !owner_id.is_empty() && owner_id.len() <= MAX_OWNER_ID_BYTES
}

fn valid_rule(rule: &DependencyClassificationRuleV1) -> bool {
    crate::identifier(&rule.rule_id, MAX_RULE_ID_BYTES) && rule.rule_version != 0
}

fn nonzero(digest: &[u8; 32]) -> bool {
    *digest != [0; 32]
}

fn encode_dependency(dependency: &InputDependencyV1) -> Value {
    Value::Array(vec![
        text(INPUT_DEPENDENCY_MAGIC_V1),
        uint(1),
        encode_node(&dependency.consumer),
        encode_node(&dependency.source),
        uint(class_code(dependency.dependency_class)),
        Value::Array(vec![
            uint(dependency.tick_range.first_tick),
            uint(dependency.tick_range.last_tick),
        ]),
        bytes(&dependency.authorization_digest),
        Value::Array(vec![
            text(&dependency.classification_rule.rule_id),
            uint(u64::from(dependency.classification_rule.rule_version)),
        ]),
        bytes(&dependency.provenance_digest),
    ])
}

fn encode_node(node: &DependencyNodeV1) -> Value {
    Value::Array(vec![
        uint(node.tick),
        uint(u64::from(node.scheduler_position)),
        text(&node.owner_id),
        uint(u64::from(node.output_ordinal)),
        uint(u64::from(node.schema_id)),
        bytes(&node.artifact_digest),
    ])
}

const fn class_code(class: DependencyClassV1) -> u64 {
    match class {
        DependencyClassV1::ExogenousFrozen => 0,
        DependencyClassV1::InterventionAssigned => 1,
        DependencyClassV1::EndogenousRecomputed => 2,
        DependencyClassV1::FixedPolicy => 3,
        DependencyClassV1::PresentationOnly => 4,
    }
}

fn decode_dependency(value: &Value) -> Result<InputDependencyV1, InputDependencyContractErrorV1> {
    let fields = array(value, FIELD_COUNT)?;
    decode_header(&fields[0], &fields[1])?;
    Ok(InputDependencyV1 {
        consumer: decode_node(&fields[2])?,
        source: decode_node(&fields[3])?,
        dependency_class: decode_class(&fields[4])?,
        tick_range: decode_tick_range(&fields[5])?,
        authorization_digest: digest_value(&fields[6])?,
        classification_rule: decode_rule(&fields[7])?,
        provenance_digest: digest_value(&fields[8])?,
    })
}

fn decode_header(magic: &Value, version: &Value) -> Result<(), InputDependencyContractErrorV1> {
    let magic = text_value(magic)?;
    let version = uint_value(version)?;
    if magic == INPUT_DEPENDENCY_MAGIC_V1 && version == 1 {
        Ok(())
    } else {
        Err(InputDependencyContractErrorV1::UnsupportedVersion)
    }
}

fn decode_node(value: &Value) -> Result<DependencyNodeV1, InputDependencyContractErrorV1> {
    let fields = array(value, NODE_FIELD_COUNT)?;
    Ok(DependencyNodeV1 {
        tick: uint_value(&fields[0])?,
        scheduler_position: u32_value(&fields[1])?,
        owner_id: text_value(&fields[2])?,
        output_ordinal: u32_value(&fields[3])?,
        schema_id: u32_value(&fields[4])?,
        artifact_digest: digest_value(&fields[5])?,
    })
}

fn decode_class(value: &Value) -> Result<DependencyClassV1, InputDependencyContractErrorV1> {
    uint_value(value).and_then(|code| match code {
        0 => Ok(DependencyClassV1::ExogenousFrozen),
        1 => Ok(DependencyClassV1::InterventionAssigned),
        2 => Ok(DependencyClassV1::EndogenousRecomputed),
        3 => Ok(DependencyClassV1::FixedPolicy),
        4 => Ok(DependencyClassV1::PresentationOnly),
        _ => Err(InputDependencyContractErrorV1::UnknownEnum),
    })
}

fn decode_tick_range(
    value: &Value,
) -> Result<DependencyTickRangeV1, InputDependencyContractErrorV1> {
    let fields = array(value, 2)?;
    Ok(DependencyTickRangeV1 {
        first_tick: uint_value(&fields[0])?,
        last_tick: uint_value(&fields[1])?,
    })
}

fn decode_rule(
    value: &Value,
) -> Result<DependencyClassificationRuleV1, InputDependencyContractErrorV1> {
    let fields = array(value, 2)?;
    Ok(DependencyClassificationRuleV1 {
        rule_id: text_value(&fields[0])?,
        rule_version: u32_value(&fields[1])?,
    })
}

fn encode_value(value: &Value) -> Result<Vec<u8>, InputDependencyContractErrorV1> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)
        .ok()
        .map(|()| encoded)
        .ok_or(InputDependencyContractErrorV1::InvalidEncoding)
}

fn decode_value(encoded: &[u8]) -> Result<Value, InputDependencyContractErrorV1> {
    preflight_cbor(encoded)?;
    let value = ciborium::from_reader::<Value, _>(encoded)
        .map_err(|_| InputDependencyContractErrorV1::InvalidEncoding)?;
    if encode_value(&value)? == encoded {
        Ok(value)
    } else {
        Err(InputDependencyContractErrorV1::InvalidEncoding)
    }
}

fn preflight_cbor(encoded: &[u8]) -> Result<(), InputDependencyContractErrorV1> {
    crate::preflight_array_cbor(encoded, MAX_NESTING_DEPTH, FIELD_COUNT as u64, false).map_err(
        |error| match error {
            crate::CborPreflightError::InvalidEncoding => {
                InputDependencyContractErrorV1::InvalidEncoding
            }
            crate::CborPreflightError::FieldOutOfBounds => {
                InputDependencyContractErrorV1::FieldOutOfBounds
            }
        },
    )
}

fn array(value: &Value, length: usize) -> Result<&[Value], InputDependencyContractErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(InputDependencyContractErrorV1::InvalidEncoding),
    }
}

fn text_value(value: &Value) -> Result<String, InputDependencyContractErrorV1> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(InputDependencyContractErrorV1::InvalidEncoding),
    }
}

fn uint_value(value: &Value) -> Result<u64, InputDependencyContractErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| InputDependencyContractErrorV1::InvalidEncoding)
        }
        _ => Err(InputDependencyContractErrorV1::InvalidEncoding),
    }
}

fn u32_value(value: &Value) -> Result<u32, InputDependencyContractErrorV1> {
    uint_value(value).and_then(|value| {
        u32::try_from(value).map_err(|_| InputDependencyContractErrorV1::FieldOutOfBounds)
    })
}

fn digest_value(value: &Value) -> Result<[u8; 32], InputDependencyContractErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| InputDependencyContractErrorV1::InvalidEncoding),
        _ => Err(InputDependencyContractErrorV1::InvalidEncoding),
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}
