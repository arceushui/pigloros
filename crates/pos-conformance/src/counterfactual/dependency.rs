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
//!
//! Two rules are contract choices where ADR-064 is silent. The source must
//! strictly precede the consumer in `(tick, scheduler_position, owner_id,
//! output_ordinal)`, which rules out self-loops and same-slot edges. The Tick
//! range must cover both endpoints but may be wider, so an edge that holds
//! across several Ticks is expressible; the proof-evidence conversion always
//! uses the exact `[source.tick, consumer.tick]` span.

use super::codec::{
    bytes_value, decode_canonical, encode_value, node_value, text_value, uint_value, CborLimits,
    FieldReader, WireError,
};
use crate::{domain_digest, DependencyClassV1, DependencyNodeV1};
use ciborium::value::Value;
use std::cmp::Ordering;

/// Magic for the standalone input-dependency record.
pub const INPUT_DEPENDENCY_MAGIC_V1: &str = "IDP1";
/// Maximum encoded size of an IDP1 input-dependency record.
pub const MAX_INPUT_DEPENDENCY_BYTES_V1: usize = 16 * 1024;

const FIELD_COUNT: usize = 9;
/// Closed dependency classes indexed by their IDP1 wire code.
const CLASSES: [DependencyClassV1; 5] = [
    DependencyClassV1::ExogenousFrozen,
    DependencyClassV1::InterventionAssigned,
    DependencyClassV1::EndogenousRecomputed,
    DependencyClassV1::FixedPolicy,
    DependencyClassV1::PresentationOnly,
];
const LIMITS: CborLimits = CborLimits {
    maximum_bytes: MAX_INPUT_DEPENDENCY_BYTES_V1,
    maximum_depth: 2,
    maximum_items: 9,
    allow_simple_values: false,
};
const MAX_OWNER_ID_BYTES: usize = 128;
const MAX_RULE_ID_BYTES: usize = 128;
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
    /// First Tick, inclusive, at which the edge holds.
    pub first_tick: u64,
    /// Last Tick, inclusive, at which the edge holds.
    pub last_tick: u64,
}

impl DependencyTickRangeV1 {
    /// Whether the inclusive range contains both `source_tick` and
    /// `consumer_tick`.
    const fn covers(&self, source_tick: u64, consumer_tick: u64) -> bool {
        self.first_tick <= source_tick && consumer_tick <= self.last_tick
    }
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
    /// Node that consumed the input.
    pub consumer: DependencyNodeV1,
    /// Node that produced the input.
    pub source: DependencyNodeV1,
    /// Closed ADR-064 class of the edge.
    pub dependency_class: DependencyClassV1,
    /// Inclusive Tick range covering both endpoints.
    pub tick_range: DependencyTickRangeV1,
    /// Digest of the authorization decision that admitted the edge.
    pub authorization_digest: [u8; 32],
    /// Rule and version that assigned the class.
    pub classification_rule: DependencyClassificationRuleV1,
    /// Digest of the edge's provenance.
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
            || !self.tick_range.covers(self.source.tick, self.consumer.tick)
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
            .and_then(|()| encode_value(&encode_dependency(self)).map_err(contract_error))
    }

    /// Decode and validate exact canonical IDP1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, oversized, or
    /// invalid IDP1 records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, InputDependencyContractErrorV1> {
        decode_canonical(bytes, LIMITS)
            .map_err(contract_error)
            .and_then(|value| decode_dependency(&value))
            .and_then(|dependency| dependency.validate().map(|()| dependency))
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
        text_value(INPUT_DEPENDENCY_MAGIC_V1),
        uint_value(1),
        node_value(&dependency.consumer),
        node_value(&dependency.source),
        uint_value(class_code(dependency.dependency_class)),
        Value::Array(vec![
            uint_value(dependency.tick_range.first_tick),
            uint_value(dependency.tick_range.last_tick),
        ]),
        bytes_value(&dependency.authorization_digest),
        Value::Array(vec![
            text_value(&dependency.classification_rule.rule_id),
            uint_value(dependency.classification_rule.rule_version.into()),
        ]),
        bytes_value(&dependency.provenance_digest),
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
    let mut fields = FieldReader::with_header(value, FIELD_COUNT, INPUT_DEPENDENCY_MAGIC_V1, 1);
    let consumer = fields.read_node();
    let source = fields.read_node();
    let dependency_class = fields.read_enum(&CLASSES, DependencyClassV1::ExogenousFrozen);
    let tick_range = fields.read_with(
        tick_range_field,
        DependencyTickRangeV1 {
            first_tick: 0,
            last_tick: 0,
        },
    );
    let authorization_digest = fields.read_bytes::<32>();
    let classification_rule = fields.read_with(
        rule_field,
        DependencyClassificationRuleV1 {
            rule_id: String::new(),
            rule_version: 0,
        },
    );
    let provenance_digest = fields.read_bytes::<32>();
    fields
        .finish()
        .map(|()| InputDependencyV1 {
            consumer,
            source,
            dependency_class,
            tick_range,
            authorization_digest,
            classification_rule,
            provenance_digest,
        })
        .map_err(contract_error)
}

fn tick_range_field(value: &Value) -> Result<DependencyTickRangeV1, WireError> {
    let mut fields = FieldReader::new(value, 2);
    let first_tick = fields.read_u64();
    let last_tick = fields.read_u64();
    fields.finish().map(|()| DependencyTickRangeV1 {
        first_tick,
        last_tick,
    })
}

fn rule_field(value: &Value) -> Result<DependencyClassificationRuleV1, WireError> {
    let mut fields = FieldReader::new(value, 2);
    let rule_id = fields.read_text();
    let rule_version = fields.read_u32();
    fields.finish().map(|()| DependencyClassificationRuleV1 {
        rule_id,
        rule_version,
    })
}

const fn contract_error(error: WireError) -> InputDependencyContractErrorV1 {
    match error {
        WireError::InvalidEncoding => InputDependencyContractErrorV1::InvalidEncoding,
        WireError::FieldOutOfBounds => InputDependencyContractErrorV1::FieldOutOfBounds,
        WireError::UnsupportedVersion => InputDependencyContractErrorV1::UnsupportedVersion,
        WireError::UnknownEnum => InputDependencyContractErrorV1::UnknownEnum,
    }
}
