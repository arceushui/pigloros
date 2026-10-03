//! Standalone ADR-064 `RCF1` frontier and `SIV1` invalidation artifacts.
//!
//! Both records already travel inside the Wave 8 proof evidence. This module
//! exposes them as standalone artifacts and owns their single strict
//! deterministic-CBOR encoding: the nested evidence codec builds its `RCF1`
//! and `SIV1` arrays through the same helpers, so the standalone and nested
//! bytes cannot drift. Validation covers the closed record contract only;
//! reachability, artifact discovery, persistence, eviction, and coordination
//! belong to the counterfactual coordinator.

use crate::{
    domain_digest, CborPreflightError, DependencyNodeV1, InvalidArtifactV1, OwnerFrontierV1,
    RecomputationFrontierV1, SuffixInvalidationReasonV1, SuffixInvalidationV1, UnknownEdgePolicyV1,
    RECOMPUTATION_FRONTIER_MAGIC_V1, SUFFIX_INVALIDATION_MAGIC_V1,
};
use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::io::Cursor;

/// Maximum encoded size of an `RCF1` recomputation frontier.
pub const MAX_RECOMPUTATION_FRONTIER_BYTES_V1: usize = 64 * 1024 * 1024;
/// Maximum encoded size of an `SIV1` suffix invalidation.
pub const MAX_SUFFIX_INVALIDATION_BYTES_V1: usize = 128 * 1024 * 1024;

const FRONTIER_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.RecomputationFrontier.v1";
const INVALIDATION_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.SuffixInvalidation.v1";
const FRONTIER_FIELDS: usize = 17;
const INVALIDATION_FIELDS: usize = 18;
const NODE_FIELDS: usize = 6;
const OWNER_FRONTIER_FIELDS: usize = 5;
const UNKNOWN_EDGE_FIELDS: usize = 2;
const INVALID_ARTIFACT_FIELDS: usize = 6;
const COMMIT_COORDINATE_FIELDS: usize = 3;
const MAX_OWNER_ID_BYTES: usize = 128;
const MAX_ARTIFACT_CLASS_BYTES: usize = 128;
const MAX_SEED_NODES: usize = 1_024;
const MAX_AFFECTED_NODES: usize = 1_000_000;
const MAX_OWNER_FRONTIERS: usize = 4_096;
const MAX_CAUSE_DIGESTS: usize = 4_096;
const MAX_UNKNOWN_EDGES: usize = 65_536;
const MAX_INVALID_ARTIFACTS: usize = 1_000_000;
const MAX_DIGEST_LIST: usize = 65_536;
const MAX_NESTING_DEPTH: u8 = 4;
const MAX_ARRAY_ITEMS: u64 = 1_000_000;

/// Closed safe errors exposed by the `RCF1` and `SIV1` contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontierArtifactErrorV1 {
    /// The bytes are malformed, noncanonical, or contain a forbidden CBOR type.
    InvalidEncoding,
    /// The record magic or schema version is not supported.
    UnsupportedVersion,
    /// An enum code lies outside its closed set.
    UnknownEnum,
    /// A required value, list, or encoded record exceeds its specified bound.
    FieldOutOfBounds,
    /// An ordered list is not in canonical ascending order.
    NonCanonicalOrder,
    /// An ordered list repeats one canonical identity.
    DuplicateIdentity,
    /// A frontier or invalidation coordinate lies outside its permitted range.
    FrontierOutOfRange,
    /// The new Fork generation is not exactly the prior generation plus one.
    PriorGenerationMismatch,
    /// The content does not match its declared record digest.
    DigestMismatch,
}

impl std::fmt::Display for FrontierArtifactErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid RCF1/SIV1 artifact encoding",
            Self::UnsupportedVersion => "unsupported RCF1/SIV1 artifact version",
            Self::UnknownEnum => "RCF1/SIV1 artifact enum code is unknown",
            Self::FieldOutOfBounds => "RCF1/SIV1 artifact field is out of bounds",
            Self::NonCanonicalOrder => "RCF1/SIV1 artifact lists are not canonical",
            Self::DuplicateIdentity => "RCF1/SIV1 artifact lists repeat an identity",
            Self::FrontierOutOfRange => "RCF1/SIV1 artifact coordinate is out of range",
            Self::PriorGenerationMismatch => "SIV1 Fork generation does not follow its prior",
            Self::DigestMismatch => "RCF1/SIV1 artifact digest does not match",
        })
    }
}

impl std::error::Error for FrontierArtifactErrorV1 {}

/// One required dependency edge that an `RCF1` frontier could not resolve.
///
/// The exact record is `[consumer_coordinate, missing_source_digest_or_null]`.
/// Entries order by consumer coordinate and then by missing source digest,
/// with an unidentified (`None`) source first.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownEdgeCoordinateV1 {
    pub consumer: DependencyNodeV1,
    pub missing_source_digest: Option<[u8; 32]>,
}

impl RecomputationFrontierV1 {
    /// Validate the closed `RCF1` contract, its encoded-size limit, and its digest.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field, ordering, coordinate range,
    /// encoded size, or the frontier digest is invalid.
    pub fn validate(&self) -> Result<(), FrontierArtifactErrorV1> {
        self.to_canonical_cbor().map(|_| ())
    }

    /// Encode this frontier as an exact 17-field deterministic-CBOR `RCF1` array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation or canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, FrontierArtifactErrorV1> {
        validate_frontier_fields(self)
            .and_then(|()| self.digest())
            .and_then(|digest| matching_digest(digest, self.frontier_digest))
            .and_then(|()| {
                encode_bounded(
                    &recomputation_frontier_value(self),
                    MAX_RECOMPUTATION_FRONTIER_BYTES_V1,
                )
            })
    }

    /// Decode and validate exact canonical `RCF1` bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for oversized, malformed, noncanonical, or
    /// invalid `RCF1` records. The size bound is checked before decoding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, FrontierArtifactErrorV1> {
        decode_bounded(bytes, MAX_RECOMPUTATION_FRONTIER_BYTES_V1)
            .and_then(|value| decode_recomputation_frontier_value(&value))
            .and_then(|frontier| frontier.validate().map(|()| frontier))
    }

    /// Compute the `RCF1` domain-separated digest over fields 0 through 15.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error if the unsigned fields cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], FrontierArtifactErrorV1> {
        unsigned_digest(frontier_fields(self), FRONTIER_DIGEST_DOMAIN_V1)
    }
}

impl SuffixInvalidationV1 {
    /// Validate the closed `SIV1` contract, its encoded-size limit, and its digest.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field, ordering, coordinate range,
    /// generation rule, encoded size, or the invalidation digest is invalid.
    pub fn validate(&self) -> Result<(), FrontierArtifactErrorV1> {
        self.to_canonical_cbor().map(|_| ())
    }

    /// Encode this invalidation as an exact 18-field deterministic-CBOR `SIV1` array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation or canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, FrontierArtifactErrorV1> {
        validate_invalidation_fields(self)
            .and_then(|()| self.digest())
            .and_then(|digest| matching_digest(digest, self.invalidation_digest))
            .and_then(|()| {
                encode_bounded(
                    &suffix_invalidation_value(self),
                    MAX_SUFFIX_INVALIDATION_BYTES_V1,
                )
            })
    }

    /// Decode and validate exact canonical `SIV1` bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for oversized, malformed, noncanonical, or
    /// invalid `SIV1` records. The size bound is checked before decoding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, FrontierArtifactErrorV1> {
        decode_bounded(bytes, MAX_SUFFIX_INVALIDATION_BYTES_V1)
            .and_then(|value| decode_suffix_invalidation_value(&value))
            .and_then(|invalidation| invalidation.validate().map(|()| invalidation))
    }

    /// Compute the `SIV1` domain-separated digest over fields 0 through 16.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error if the unsigned fields cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], FrontierArtifactErrorV1> {
        unsigned_digest(invalidation_fields(self), INVALIDATION_DIGEST_DOMAIN_V1)
    }
}

/// Build the exact `RCF1` array shared by the standalone and nested codecs.
pub(crate) fn recomputation_frontier_value(frontier: &RecomputationFrontierV1) -> Value {
    Value::Array(frontier_fields(frontier))
}

/// Build the exact `SIV1` array shared by the standalone and nested codecs.
pub(crate) fn suffix_invalidation_value(invalidation: &SuffixInvalidationV1) -> Value {
    Value::Array(invalidation_fields(invalidation))
}

/// Build the exact six-field dependency-node coordinate.
pub(crate) fn dependency_node_value(node: &DependencyNodeV1) -> Value {
    Value::Array(vec![
        uint(node.tick),
        uint(u64::from(node.scheduler_position)),
        text(&node.owner_id),
        uint(u64::from(node.output_ordinal)),
        uint(u64::from(node.schema_id)),
        bytes(&node.artifact_digest),
    ])
}

/// Decode the `RCF1` array shape without validating bounds, order, or digest.
pub(crate) fn decode_recomputation_frontier_value(
    value: &Value,
) -> Result<RecomputationFrontierV1, FrontierArtifactErrorV1> {
    let fields = array(value, FRONTIER_FIELDS)?;
    validate_header(fields, RECOMPUTATION_FRONTIER_MAGIC_V1)?;
    Ok(RecomputationFrontierV1 {
        frontier_id: fixed_bytes(&fields[2])?,
        plan_digest: fixed_bytes(&fields[3])?,
        parent_cut_digest: fixed_bytes(&fields[4])?,
        dependency_graph_digest: fixed_bytes(&fields[5])?,
        intervention_seed_nodes: decode_list(&fields[6], decode_node)?,
        affected_nodes: decode_list(&fields[7], decode_node)?,
        owner_frontiers: decode_list(&fields[8], decode_owner_frontier)?,
        global_frontier_tick: uint_value(&fields[9])?,
        global_frontier_scheduler_position: u32_value(&fields[10])?,
        unknown_edge_policy: decode_unknown_edge_policy(&fields[11])?,
        unknown_edge_coordinates: decode_list(&fields[12], decode_unknown_edge)?,
        endogenous_suffix_end_tick: uint_value(&fields[13])?,
        classification_bundle_digest: fixed_bytes(&fields[14])?,
        provenance_digest: fixed_bytes(&fields[15])?,
        frontier_digest: fixed_bytes(&fields[16])?,
    })
}

/// Decode the `SIV1` array shape without validating bounds, order, or digest.
pub(crate) fn decode_suffix_invalidation_value(
    value: &Value,
) -> Result<SuffixInvalidationV1, FrontierArtifactErrorV1> {
    let fields = array(value, INVALIDATION_FIELDS)?;
    validate_header(fields, SUFFIX_INVALIDATION_MAGIC_V1)?;
    let commit_coordinate = array(&fields[15], COMMIT_COORDINATE_FIELDS)?;
    Ok(SuffixInvalidationV1 {
        invalidation_id: fixed_bytes(&fields[2])?,
        plan_digest: fixed_bytes(&fields[3])?,
        fork_id: fixed_bytes(&fields[4])?,
        prior_generation: uint_value(&fields[5])?,
        new_generation: uint_value(&fields[6])?,
        frontier_digest: fixed_bytes(&fields[7])?,
        invalid_start: decode_node(&fields[8])?,
        invalid_end: decode_node(&fields[9])?,
        invalid_artifacts: decode_list(&fields[10], decode_invalid_artifact)?,
        invalid_checkpoint_digests: decode_list(&fields[11], fixed_bytes::<32>)?,
        invalid_projection_digests: decode_list(&fields[12], fixed_bytes::<32>)?,
        retained_exogenous_digests: decode_list(&fields[13], fixed_bytes::<32>)?,
        reason: decode_invalidation_reason(&fields[14])?,
        commit_timeline_id: fixed_bytes(&commit_coordinate[0])?,
        commit_seq: uint_value(&commit_coordinate[1])?,
        commit_tick: uint_value(&commit_coordinate[2])?,
        provenance_digest: fixed_bytes(&fields[16])?,
        invalidation_digest: fixed_bytes(&fields[17])?,
    })
}

fn validate_frontier_fields(
    frontier: &RecomputationFrontierV1,
) -> Result<(), FrontierArtifactErrorV1> {
    if !counted(frontier.intervention_seed_nodes.len(), MAX_SEED_NODES)
        || !counted(frontier.affected_nodes.len(), MAX_AFFECTED_NODES)
        || !counted(frontier.owner_frontiers.len(), MAX_OWNER_FRONTIERS)
        || frontier.unknown_edge_coordinates.len() > MAX_UNKNOWN_EDGES
        || !frontier.intervention_seed_nodes.iter().all(valid_node)
        || !frontier.affected_nodes.iter().all(valid_node)
        || !frontier.owner_frontiers.iter().all(valid_owner_frontier)
        || !frontier
            .unknown_edge_coordinates
            .iter()
            .all(|edge| valid_node(&edge.consumer))
        || unknown_edges_contradict_policy(frontier)
    {
        return Err(FrontierArtifactErrorV1::FieldOutOfBounds);
    }
    ordered(&frontier.intervention_seed_nodes, Ord::cmp)
        .and_then(|()| ordered(&frontier.affected_nodes, Ord::cmp))
        .and_then(|()| validate_owner_frontiers(&frontier.owner_frontiers))
        .and_then(|()| ordered(&frontier.unknown_edge_coordinates, Ord::cmp))
        .and_then(|()| validate_frontier_range(frontier))
}

/// `Reject` never records unknown edges; `FullSuffixFromCut` must record them.
const fn unknown_edges_contradict_policy(frontier: &RecomputationFrontierV1) -> bool {
    match frontier.unknown_edge_policy {
        UnknownEdgePolicyV1::Reject => !frontier.unknown_edge_coordinates.is_empty(),
        UnknownEdgePolicyV1::FullSuffixFromCut => frontier.unknown_edge_coordinates.is_empty(),
    }
}

/// Owner frontiers sort by coordinate, and each owner appears exactly once.
fn validate_owner_frontiers(owners: &[OwnerFrontierV1]) -> Result<(), FrontierArtifactErrorV1> {
    let mut owner_ids = BTreeSet::new();
    ordered(owners, compare_owner_frontiers).and_then(|()| {
        owners.iter().try_for_each(|owner| {
            if owner_ids.insert(owner.owner_id.as_str()) {
                ordered(&owner.cause_node_digests, Ord::cmp)
            } else {
                Err(FrontierArtifactErrorV1::DuplicateIdentity)
            }
        })
    })
}

fn compare_owner_frontiers(left: &OwnerFrontierV1, right: &OwnerFrontierV1) -> Ordering {
    (
        left.earliest_tick,
        left.earliest_scheduler_position,
        left.owner_id.as_bytes(),
        left.earliest_output_ordinal,
    )
        .cmp(&(
            right.earliest_tick,
            right.earliest_scheduler_position,
            right.owner_id.as_bytes(),
            right.earliest_output_ordinal,
        ))
}

/// The suffix ends no earlier than the global frontier, which is never later
/// than the lowest owner frontier.
fn validate_frontier_range(
    frontier: &RecomputationFrontierV1,
) -> Result<(), FrontierArtifactErrorV1> {
    let global = (
        frontier.global_frontier_tick,
        frontier.global_frontier_scheduler_position,
    );
    if frontier.endogenous_suffix_end_tick < frontier.global_frontier_tick
        || frontier
            .owner_frontiers
            .iter()
            .any(|owner| (owner.earliest_tick, owner.earliest_scheduler_position) < global)
    {
        Err(FrontierArtifactErrorV1::FrontierOutOfRange)
    } else {
        Ok(())
    }
}

fn validate_invalidation_fields(
    invalidation: &SuffixInvalidationV1,
) -> Result<(), FrontierArtifactErrorV1> {
    if invalidation.invalid_artifacts.len() > MAX_INVALID_ARTIFACTS
        || invalidation.invalid_checkpoint_digests.len() > MAX_DIGEST_LIST
        || invalidation.invalid_projection_digests.len() > MAX_DIGEST_LIST
        || invalidation.retained_exogenous_digests.len() > MAX_DIGEST_LIST
        || !valid_node(&invalidation.invalid_start)
        || !valid_node(&invalidation.invalid_end)
        || !invalidation
            .invalid_artifacts
            .iter()
            .all(valid_invalid_artifact)
    {
        return Err(FrontierArtifactErrorV1::FieldOutOfBounds);
    }
    if invalidation.prior_generation.checked_add(1) != Some(invalidation.new_generation) {
        return Err(FrontierArtifactErrorV1::PriorGenerationMismatch);
    }
    if invalidation.invalid_end < invalidation.invalid_start {
        return Err(FrontierArtifactErrorV1::FrontierOutOfRange);
    }
    ordered(&invalidation.invalid_artifacts, compare_invalid_artifacts)
        .and_then(|()| ordered(&invalidation.invalid_checkpoint_digests, Ord::cmp))
        .and_then(|()| ordered(&invalidation.invalid_projection_digests, Ord::cmp))
        .and_then(|()| ordered(&invalidation.retained_exogenous_digests, Ord::cmp))
}

fn compare_invalid_artifacts(left: &InvalidArtifactV1, right: &InvalidArtifactV1) -> Ordering {
    (
        left.producer.tick,
        left.producer.scheduler_position,
        left.producer.owner_id.as_bytes(),
        left.producer.output_ordinal,
        left.artifact_class.as_bytes(),
        left.artifact_digest,
    )
        .cmp(&(
            right.producer.tick,
            right.producer.scheduler_position,
            right.producer.owner_id.as_bytes(),
            right.producer.output_ordinal,
            right.artifact_class.as_bytes(),
            right.artifact_digest,
        ))
}

/// Every bounded list or identifier here holds between one and `maximum` items.
const fn counted(length: usize, maximum: usize) -> bool {
    length != 0 && length <= maximum
}

const fn valid_node(node: &DependencyNodeV1) -> bool {
    counted(node.owner_id.len(), MAX_OWNER_ID_BYTES)
}

const fn valid_owner_frontier(owner: &OwnerFrontierV1) -> bool {
    counted(owner.owner_id.len(), MAX_OWNER_ID_BYTES)
        && counted(owner.cause_node_digests.len(), MAX_CAUSE_DIGESTS)
}

const fn valid_invalid_artifact(artifact: &InvalidArtifactV1) -> bool {
    counted(artifact.artifact_class.len(), MAX_ARTIFACT_CLASS_BYTES)
        && valid_node(&artifact.producer)
}

/// Accept only strictly ascending lists; an equal neighbour is a duplicate.
fn ordered<T>(
    values: &[T],
    compare: impl Fn(&T, &T) -> Ordering,
) -> Result<(), FrontierArtifactErrorV1> {
    values
        .windows(2)
        .try_for_each(|pair| match compare(&pair[0], &pair[1]) {
            Ordering::Less => Ok(()),
            Ordering::Equal => Err(FrontierArtifactErrorV1::DuplicateIdentity),
            Ordering::Greater => Err(FrontierArtifactErrorV1::NonCanonicalOrder),
        })
}

fn matching_digest(computed: [u8; 32], declared: [u8; 32]) -> Result<(), FrontierArtifactErrorV1> {
    if computed == declared {
        Ok(())
    } else {
        Err(FrontierArtifactErrorV1::DigestMismatch)
    }
}

/// Hash every field except the trailing record digest.
fn unsigned_digest(
    mut fields: Vec<Value>,
    domain: &[u8],
) -> Result<[u8; 32], FrontierArtifactErrorV1> {
    fields.truncate(fields.len() - 1);
    encode_value(&Value::Array(fields)).map(|unsigned| domain_digest(domain, &unsigned))
}

fn frontier_fields(frontier: &RecomputationFrontierV1) -> Vec<Value> {
    vec![
        text(RECOMPUTATION_FRONTIER_MAGIC_V1),
        uint(1),
        bytes(&frontier.frontier_id),
        bytes(&frontier.plan_digest),
        bytes(&frontier.parent_cut_digest),
        bytes(&frontier.dependency_graph_digest),
        node_list(&frontier.intervention_seed_nodes),
        node_list(&frontier.affected_nodes),
        Value::Array(
            frontier
                .owner_frontiers
                .iter()
                .map(owner_frontier_value)
                .collect(),
        ),
        uint(frontier.global_frontier_tick),
        uint(u64::from(frontier.global_frontier_scheduler_position)),
        uint(unknown_edge_policy_code(frontier.unknown_edge_policy)),
        Value::Array(
            frontier
                .unknown_edge_coordinates
                .iter()
                .map(unknown_edge_value)
                .collect(),
        ),
        uint(frontier.endogenous_suffix_end_tick),
        bytes(&frontier.classification_bundle_digest),
        bytes(&frontier.provenance_digest),
        bytes(&frontier.frontier_digest),
    ]
}

fn invalidation_fields(invalidation: &SuffixInvalidationV1) -> Vec<Value> {
    vec![
        text(SUFFIX_INVALIDATION_MAGIC_V1),
        uint(1),
        bytes(&invalidation.invalidation_id),
        bytes(&invalidation.plan_digest),
        bytes(&invalidation.fork_id),
        uint(invalidation.prior_generation),
        uint(invalidation.new_generation),
        bytes(&invalidation.frontier_digest),
        dependency_node_value(&invalidation.invalid_start),
        dependency_node_value(&invalidation.invalid_end),
        Value::Array(
            invalidation
                .invalid_artifacts
                .iter()
                .map(invalid_artifact_value)
                .collect(),
        ),
        digest_list(&invalidation.invalid_checkpoint_digests),
        digest_list(&invalidation.invalid_projection_digests),
        digest_list(&invalidation.retained_exogenous_digests),
        uint(invalidation_reason_code(invalidation.reason)),
        Value::Array(vec![
            bytes(&invalidation.commit_timeline_id),
            uint(invalidation.commit_seq),
            uint(invalidation.commit_tick),
        ]),
        bytes(&invalidation.provenance_digest),
        bytes(&invalidation.invalidation_digest),
    ]
}

fn owner_frontier_value(owner: &OwnerFrontierV1) -> Value {
    Value::Array(vec![
        text(&owner.owner_id),
        uint(owner.earliest_tick),
        uint(u64::from(owner.earliest_scheduler_position)),
        uint(u64::from(owner.earliest_output_ordinal)),
        digest_list(&owner.cause_node_digests),
    ])
}

fn unknown_edge_value(edge: &UnknownEdgeCoordinateV1) -> Value {
    Value::Array(vec![
        dependency_node_value(&edge.consumer),
        edge.missing_source_digest
            .map_or(Value::Null, |digest| bytes(&digest)),
    ])
}

fn invalid_artifact_value(artifact: &InvalidArtifactV1) -> Value {
    Value::Array(vec![
        text(&artifact.artifact_class),
        uint(u64::from(artifact.schema_id)),
        bytes(&artifact.artifact_digest),
        dependency_node_value(&artifact.producer),
        uint(artifact.prior_generation),
        uint(invalidation_reason_code(artifact.reason)),
    ])
}

fn node_list(nodes: &[DependencyNodeV1]) -> Value {
    Value::Array(nodes.iter().map(dependency_node_value).collect())
}

fn digest_list(digests: &[[u8; 32]]) -> Value {
    Value::Array(
        digests
            .iter()
            .map(|digest| bytes(digest.as_slice()))
            .collect(),
    )
}

const fn unknown_edge_policy_code(policy: UnknownEdgePolicyV1) -> u64 {
    match policy {
        UnknownEdgePolicyV1::Reject => 0,
        UnknownEdgePolicyV1::FullSuffixFromCut => 1,
    }
}

const fn invalidation_reason_code(reason: SuffixInvalidationReasonV1) -> u64 {
    match reason {
        SuffixInvalidationReasonV1::NewIntervention => 0,
        SuffixInvalidationReasonV1::ChangedIntervention => 1,
        SuffixInvalidationReasonV1::UnknownEdgeFallback => 2,
        SuffixInvalidationReasonV1::RetryAfterAtomicFailure => 3,
        SuffixInvalidationReasonV1::TrustOrErasureChange => 4,
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn decode_node(value: &Value) -> Result<DependencyNodeV1, FrontierArtifactErrorV1> {
    let fields = array(value, NODE_FIELDS)?;
    Ok(DependencyNodeV1 {
        tick: uint_value(&fields[0])?,
        scheduler_position: u32_value(&fields[1])?,
        owner_id: text_value(&fields[2])?,
        output_ordinal: u32_value(&fields[3])?,
        schema_id: u32_value(&fields[4])?,
        artifact_digest: fixed_bytes(&fields[5])?,
    })
}

fn decode_owner_frontier(value: &Value) -> Result<OwnerFrontierV1, FrontierArtifactErrorV1> {
    let fields = array(value, OWNER_FRONTIER_FIELDS)?;
    Ok(OwnerFrontierV1 {
        owner_id: text_value(&fields[0])?,
        earliest_tick: uint_value(&fields[1])?,
        earliest_scheduler_position: u32_value(&fields[2])?,
        earliest_output_ordinal: u32_value(&fields[3])?,
        cause_node_digests: decode_list(&fields[4], fixed_bytes::<32>)?,
    })
}

fn decode_unknown_edge(value: &Value) -> Result<UnknownEdgeCoordinateV1, FrontierArtifactErrorV1> {
    let fields = array(value, UNKNOWN_EDGE_FIELDS)?;
    Ok(UnknownEdgeCoordinateV1 {
        consumer: decode_node(&fields[0])?,
        missing_source_digest: match &fields[1] {
            Value::Null => None,
            digest => Some(fixed_bytes(digest)?),
        },
    })
}

fn decode_invalid_artifact(value: &Value) -> Result<InvalidArtifactV1, FrontierArtifactErrorV1> {
    let fields = array(value, INVALID_ARTIFACT_FIELDS)?;
    Ok(InvalidArtifactV1 {
        artifact_class: text_value(&fields[0])?,
        schema_id: u32_value(&fields[1])?,
        artifact_digest: fixed_bytes(&fields[2])?,
        producer: decode_node(&fields[3])?,
        prior_generation: uint_value(&fields[4])?,
        reason: decode_invalidation_reason(&fields[5])?,
    })
}

fn decode_unknown_edge_policy(
    value: &Value,
) -> Result<UnknownEdgePolicyV1, FrontierArtifactErrorV1> {
    match uint_value(value)? {
        0 => Ok(UnknownEdgePolicyV1::Reject),
        1 => Ok(UnknownEdgePolicyV1::FullSuffixFromCut),
        _ => Err(FrontierArtifactErrorV1::UnknownEnum),
    }
}

fn decode_invalidation_reason(
    value: &Value,
) -> Result<SuffixInvalidationReasonV1, FrontierArtifactErrorV1> {
    match uint_value(value)? {
        0 => Ok(SuffixInvalidationReasonV1::NewIntervention),
        1 => Ok(SuffixInvalidationReasonV1::ChangedIntervention),
        2 => Ok(SuffixInvalidationReasonV1::UnknownEdgeFallback),
        3 => Ok(SuffixInvalidationReasonV1::RetryAfterAtomicFailure),
        4 => Ok(SuffixInvalidationReasonV1::TrustOrErasureChange),
        _ => Err(FrontierArtifactErrorV1::UnknownEnum),
    }
}

/// Fields 0 and 1 carry the exact four-byte magic and schema version 1.
fn validate_header(fields: &[Value], magic: &str) -> Result<(), FrontierArtifactErrorV1> {
    if text_value(&fields[0])? == magic && uint_value(&fields[1])? == 1 {
        Ok(())
    } else {
        Err(FrontierArtifactErrorV1::UnsupportedVersion)
    }
}

fn decode_list<T>(
    value: &Value,
    decode: fn(&Value) -> Result<T, FrontierArtifactErrorV1>,
) -> Result<Vec<T>, FrontierArtifactErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(decode).collect(),
        _ => Err(FrontierArtifactErrorV1::InvalidEncoding),
    }
}

fn array(value: &Value, length: usize) -> Result<&[Value], FrontierArtifactErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(FrontierArtifactErrorV1::InvalidEncoding),
    }
}

fn text_value(value: &Value) -> Result<String, FrontierArtifactErrorV1> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(FrontierArtifactErrorV1::InvalidEncoding),
    }
}

fn uint_value(value: &Value) -> Result<u64, FrontierArtifactErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| FrontierArtifactErrorV1::InvalidEncoding)
        }
        _ => Err(FrontierArtifactErrorV1::InvalidEncoding),
    }
}

fn u32_value(value: &Value) -> Result<u32, FrontierArtifactErrorV1> {
    uint_value(value).and_then(|value| {
        u32::try_from(value).map_err(|_| FrontierArtifactErrorV1::FieldOutOfBounds)
    })
}

fn fixed_bytes<const LENGTH: usize>(
    value: &Value,
) -> Result<[u8; LENGTH], FrontierArtifactErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| FrontierArtifactErrorV1::InvalidEncoding),
        _ => Err(FrontierArtifactErrorV1::InvalidEncoding),
    }
}

/// One size rule serves both directions so encode and decode cannot disagree.
const fn within_size(length: usize, maximum: usize) -> Result<(), FrontierArtifactErrorV1> {
    if length > maximum {
        Err(FrontierArtifactErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn encode_bounded(value: &Value, maximum: usize) -> Result<Vec<u8>, FrontierArtifactErrorV1> {
    encode_value(value).and_then(|encoded| within_size(encoded.len(), maximum).map(|()| encoded))
}

/// Bound the input, then preflight nesting and list lengths before any
/// allocation, then require the exact canonical re-encoding.
fn decode_bounded(bytes: &[u8], maximum: usize) -> Result<Value, FrontierArtifactErrorV1> {
    within_size(bytes.len(), maximum)
        .and_then(|()| {
            crate::preflight_array_cbor(bytes, MAX_NESTING_DEPTH, MAX_ARRAY_ITEMS, true)
                .map_err(preflight_error)
        })
        .and_then(|()| {
            ciborium::from_reader::<Value, _>(Cursor::new(bytes))
                .map_err(|_| FrontierArtifactErrorV1::InvalidEncoding)
        })
        .and_then(|value| {
            encode_value(&value).and_then(|canonical| {
                if canonical == bytes {
                    Ok(value)
                } else {
                    Err(FrontierArtifactErrorV1::InvalidEncoding)
                }
            })
        })
}

const fn preflight_error(error: CborPreflightError) -> FrontierArtifactErrorV1 {
    match error {
        CborPreflightError::InvalidEncoding => FrontierArtifactErrorV1::InvalidEncoding,
        CborPreflightError::FieldOutOfBounds => FrontierArtifactErrorV1::FieldOutOfBounds,
    }
}

fn encode_value(value: &Value) -> Result<Vec<u8>, FrontierArtifactErrorV1> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)
        .map(|()| encoded)
        .or(Err(FrontierArtifactErrorV1::InvalidEncoding))
}
