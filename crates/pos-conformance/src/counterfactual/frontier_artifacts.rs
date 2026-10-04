//! Standalone ADR-064 `RCF1` frontier and `SIV1` invalidation artifacts.
//!
//! Both records already travel inside the Wave 8 proof evidence. This module
//! exposes them as standalone artifacts and owns their single strict
//! deterministic-CBOR encoding: the nested evidence codec builds its `RCF1`
//! and `SIV1` arrays through the same helpers, so the standalone and nested
//! bytes cannot drift. Validation covers the closed record contract only;
//! reachability, artifact discovery, persistence, eviction, and coordination
//! belong to the counterfactual coordinator.
//!
//! A standalone `RCF1` follows the ADR-064 bounds: it carries at least one
//! Intervention seed, one affected node, and one owner frontier. The nested
//! evidence verifier also admits a no-Intervention baseline frontier whose
//! lists are empty; such a baseline frontier is not an exportable `RCF1` and
//! is rejected here. The standalone validator rejects every all-zero digest
//! the nested verifier rejects, and additionally a zero missing-source digest
//! (an unknown source is `null`), so a standalone-valid record never fails the
//! nested digest rules. Likewise every artifact-naming node needs a nonzero
//! schema, and each invalid artifact carries its producer's schema and the
//! record's reason and sorts by the full producer node, then class and digest.
//! Beyond the nested verifier, a standalone `SIV1` also requires a nonzero
//! Fork ID and every invalid artifact's prior generation to equal the
//! record's prior generation.
//!
//! Every list count is checked before any per-item rule, digest, or encoding,
//! so an oversized list is rejected without encoding any CBOR.

use super::codec::{
    bytes_value, decode_canonical, decode_node, encode_value, node_value, nonzero, text_value,
    uint_value, CborLimits, FieldFailure, FieldReader, WireError,
};
use super::dependency::MAX_DEPENDENCY_OWNER_ID_BYTES_V1;
use crate::{
    domain_digest, DependencyNodeV1, InvalidArtifactV1, OwnerFrontierV1, RecomputationFrontierV1,
    SuffixInvalidationReasonV1, SuffixInvalidationV1, UnknownEdgePolicyV1,
    RECOMPUTATION_FRONTIER_MAGIC_V1, SUFFIX_INVALIDATION_MAGIC_V1,
};
use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Maximum encoded size of an `RCF1` recomputation frontier.
pub const MAX_RECOMPUTATION_FRONTIER_BYTES_V1: usize = 64 * 1024 * 1024;
/// Maximum encoded size of an `SIV1` suffix invalidation.
pub const MAX_SUFFIX_INVALIDATION_BYTES_V1: usize = 128 * 1024 * 1024;
/// Maximum number of unknown-edge coordinates recorded by one `RCF1`
/// frontier under `FullSuffixFromCut`.
pub const MAX_UNKNOWN_EDGE_COORDINATES_V1: usize = 65_536;
/// Maximum number of cause-node digests carried by one owner frontier.
pub const MAX_CAUSE_DIGESTS_V1: usize = 4_096;

const FRONTIER_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.RecomputationFrontier.v1";
const INVALIDATION_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.SuffixInvalidation.v1";
const FRONTIER_FIELDS: usize = 17;
const INVALIDATION_FIELDS: usize = 18;
const OWNER_FRONTIER_FIELDS: usize = 5;
const UNKNOWN_EDGE_FIELDS: usize = 2;
const INVALID_ARTIFACT_FIELDS: usize = 6;
const COMMIT_COORDINATE_FIELDS: usize = 3;
const MAX_ARTIFACT_CLASS_BYTES: usize = 128;
const MAX_SEED_NODES: usize = 1_024;
const MAX_AFFECTED_NODES: usize = 1_000_000;
const MAX_OWNER_FRONTIERS: usize = 4_096;
const MAX_INVALID_ARTIFACTS: usize = 1_000_000;
const MAX_DIGEST_LIST: usize = 65_536;
const FRONTIER_LIMITS: CborLimits = CborLimits {
    maximum_bytes: MAX_RECOMPUTATION_FRONTIER_BYTES_V1,
    maximum_depth: 4,
    maximum_items: 1_000_000,
    allow_simple_values: true,
};
/// Encoded size of the trailing record digest, a `bstr(32)`: the two-byte
/// header `0x58 0x20` followed by the 32 digest bytes.
const DIGEST_FIELD_BYTES: usize = 34;
const INVALIDATION_LIMITS: CborLimits = CborLimits {
    maximum_bytes: MAX_SUFFIX_INVALIDATION_BYTES_V1,
    ..FRONTIER_LIMITS
};
/// Closed invalidation reasons indexed by their `SIV1` wire code.
const REASONS: [SuffixInvalidationReasonV1; 5] = [
    SuffixInvalidationReasonV1::NewIntervention,
    SuffixInvalidationReasonV1::ChangedIntervention,
    SuffixInvalidationReasonV1::UnknownEdgeFallback,
    SuffixInvalidationReasonV1::RetryAfterAtomicFailure,
    SuffixInvalidationReasonV1::TrustOrErasureChange,
];
/// Nested-evidence field names of one node coordinate, by reader slot.
const NODE_FIELD_NAMES: [&str; 7] = [
    "dependency_node",
    "node_tick",
    "node_scheduler",
    "node_owner",
    "node_ordinal",
    "node_schema",
    "node_digest",
];
/// Nested-evidence field names of one owner frontier, by item reader slot.
const OWNER_FRONTIER_FIELD_NAMES: [&str; 6] = [
    "owner_frontier",
    "frontier_owner",
    "frontier_tick",
    "frontier_scheduler",
    "frontier_ordinal",
    "frontier_causes",
];
/// Nested-evidence field names of one unknown-edge coordinate, by item reader
/// slot; the consumer node takes the seven node slots.
const UNKNOWN_EDGE_FIELD_NAMES: [&str; 9] = [
    "unknown_edge",
    NODE_FIELD_NAMES[0],
    NODE_FIELD_NAMES[1],
    NODE_FIELD_NAMES[2],
    NODE_FIELD_NAMES[3],
    NODE_FIELD_NAMES[4],
    NODE_FIELD_NAMES[5],
    NODE_FIELD_NAMES[6],
    "unknown_edge_source",
];
/// Nested-evidence field names of one invalid artifact, by item reader slot;
/// the producer node takes the seven node slots.
const INVALID_ARTIFACT_FIELD_NAMES: [&str; 13] = [
    "invalid_artifact",
    "artifact_class",
    "artifact_schema",
    "artifact_digest",
    NODE_FIELD_NAMES[0],
    NODE_FIELD_NAMES[1],
    NODE_FIELD_NAMES[2],
    NODE_FIELD_NAMES[3],
    NODE_FIELD_NAMES[4],
    NODE_FIELD_NAMES[5],
    NODE_FIELD_NAMES[6],
    "artifact_generation",
    "invalidation_reason",
];
/// `RCF1` reader slots of the record lists whose items are named by field.
const FRONTIER_SEEDS_SLOT: usize = 7;
const FRONTIER_AFFECTED_SLOT: usize = 8;
const FRONTIER_OWNERS_SLOT: usize = 9;
const FRONTIER_UNKNOWN_EDGES_SLOT: usize = 13;
/// `SIV1` reader slot of the invalid-artifact list.
const INVALID_ARTIFACTS_SLOT: usize = 23;
/// Nested-evidence field names of an `RCF1` record, by reader slot.
const FRONTIER_FIELD_NAMES: [&str; 18] = [
    "recomputation_frontier",
    "frontier_magic",
    "frontier_version",
    "frontier_id",
    "frontier_plan",
    "frontier_parent_cut",
    "frontier_graph",
    "frontier_seeds",
    "frontier_affected",
    "frontier_owners",
    "frontier_global_tick",
    "frontier_global_scheduler",
    "frontier_unknown_policy",
    "frontier_unknown_edges",
    "frontier_end_tick",
    "frontier_classification",
    "frontier_provenance",
    "frontier_digest",
];
/// Nested-evidence field names of an `SIV1` record, by reader slot; the two
/// range endpoints each take the seven node slots.
const INVALIDATION_FIELD_NAMES: [&str; 34] = [
    "suffix_invalidation",
    "invalidation_magic",
    "invalidation_version",
    "invalidation_id",
    "invalidation_plan",
    "invalidation_fork",
    "invalidation_prior_generation",
    "invalidation_new_generation",
    "invalidation_frontier",
    NODE_FIELD_NAMES[0],
    NODE_FIELD_NAMES[1],
    NODE_FIELD_NAMES[2],
    NODE_FIELD_NAMES[3],
    NODE_FIELD_NAMES[4],
    NODE_FIELD_NAMES[5],
    NODE_FIELD_NAMES[6],
    NODE_FIELD_NAMES[0],
    NODE_FIELD_NAMES[1],
    NODE_FIELD_NAMES[2],
    NODE_FIELD_NAMES[3],
    NODE_FIELD_NAMES[4],
    NODE_FIELD_NAMES[5],
    NODE_FIELD_NAMES[6],
    "invalid_artifacts",
    "invalid_checkpoints",
    "invalid_projections",
    "retained_exogenous",
    "invalidation_reason",
    "invalidation_commit_coordinate",
    "invalidation_commit_timeline",
    "invalidation_commit_seq",
    "invalidation_commit_tick",
    "invalidation_provenance",
    "invalidation_digest",
];

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

impl UnknownEdgePolicyV1 {
    /// Every unknown-edge policy, indexed by its wire code.
    ///
    /// This is the one wire-code table shared by `RCF1`, `CFP1`, and every
    /// consumer outside this crate.
    pub const ALL_V1: [Self; 2] = [Self::Reject, Self::FullSuffixFromCut];

    /// Stable wire code of this policy: its index in [`Self::ALL_V1`].
    #[must_use]
    pub const fn wire_code(self) -> u8 {
        self as u8
    }
}

impl RecomputationFrontierV1 {
    /// Validate the fields, then return this frontier with its
    /// `frontier_digest` computed.
    ///
    /// The field list is built and its unsigned fields encoded once, for both
    /// the digest and the size bound.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field, ordering, coordinate range,
    /// or the encoded size is invalid.
    pub fn seal(mut self) -> Result<Self, FrontierArtifactErrorV1> {
        validate_frontier_fields(&self)
            .and_then(|()| {
                unsigned_encoding(
                    &frontier_fields(&self),
                    FRONTIER_DIGEST_DOMAIN_V1,
                    MAX_RECOMPUTATION_FRONTIER_BYTES_V1,
                )
            })
            .map(|(digest, _)| {
                self.frontier_digest = digest;
                self
            })
    }

    /// Validate the closed `RCF1` contract, its encoded-size limit, and its digest.
    ///
    /// The seed, affected-node, and owner-frontier lists must each be
    /// non-empty. A no-Intervention baseline frontier, which the nested
    /// evidence verifier admits with empty lists, is not an exportable `RCF1`
    /// and fails here with [`FrontierArtifactErrorV1::FieldOutOfBounds`].
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field, ordering, coordinate range,
    /// encoded size, or the frontier digest is invalid.
    pub fn validate(&self) -> Result<(), FrontierArtifactErrorV1> {
        self.verified_unsigned().map(drop)
    }

    /// Encode this frontier as an exact 17-field deterministic-CBOR `RCF1` array.
    ///
    /// The unsigned fields are encoded once for the digest check and extended
    /// in place by the digest into the returned bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation or canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, FrontierArtifactErrorV1> {
        self.verified_unsigned()
            .map(|unsigned| signed_encoding(unsigned, self.frontier_digest))
    }

    /// Validate the fields and return the unsigned encoding whose digest
    /// matches the declared `frontier_digest`.
    fn verified_unsigned(&self) -> Result<Vec<u8>, FrontierArtifactErrorV1> {
        validate_frontier_fields(self)
            .and_then(|()| {
                unsigned_encoding(
                    &frontier_fields(self),
                    FRONTIER_DIGEST_DOMAIN_V1,
                    MAX_RECOMPUTATION_FRONTIER_BYTES_V1,
                )
            })
            .and_then(|(digest, unsigned)| {
                matching_digest(digest, self.frontier_digest).map(|()| unsigned)
            })
    }

    /// Decode and validate exact canonical `RCF1` bytes.
    ///
    /// The size bound is checked before decoding, and the only encoding after
    /// the canonical round-trip check is the one the digest needs.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for oversized, malformed, noncanonical, or
    /// invalid `RCF1` records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, FrontierArtifactErrorV1> {
        decode_bounded(bytes, FRONTIER_LIMITS)
            .and_then(|value| {
                decode_frontier(&value).map_err(|failure| contract_error(failure.error))
            })
            .and_then(|frontier| {
                validate_frontier_fields(&frontier)
                    .and_then(|()| {
                        verify_record_digest(
                            &frontier_fields(&frontier),
                            frontier.frontier_digest,
                            FRONTIER_DIGEST_DOMAIN_V1,
                        )
                    })
                    .map(|()| frontier)
            })
    }

    /// Compute the `RCF1` domain-separated digest over fields 0 through 15.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error if the unsigned fields cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], FrontierArtifactErrorV1> {
        unsigned_digest(&frontier_fields(self), FRONTIER_DIGEST_DOMAIN_V1)
    }
}

impl SuffixInvalidationV1 {
    /// Validate the fields, then return this invalidation with its
    /// `invalidation_digest` computed.
    ///
    /// The field list is built and its unsigned fields encoded once, for both
    /// the digest and the size bound.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field, ordering, coordinate range,
    /// generation rule, or the encoded size is invalid.
    pub fn seal(mut self) -> Result<Self, FrontierArtifactErrorV1> {
        validate_invalidation_fields(&self)
            .and_then(|()| {
                unsigned_encoding(
                    &invalidation_fields(&self),
                    INVALIDATION_DIGEST_DOMAIN_V1,
                    MAX_SUFFIX_INVALIDATION_BYTES_V1,
                )
            })
            .map(|(digest, _)| {
                self.invalidation_digest = digest;
                self
            })
    }

    /// Validate the closed `SIV1` contract, its encoded-size limit, and its digest.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field, ordering, coordinate range,
    /// generation rule, encoded size, or the invalidation digest is invalid.
    pub fn validate(&self) -> Result<(), FrontierArtifactErrorV1> {
        self.verified_unsigned().map(drop)
    }

    /// Encode this invalidation as an exact 18-field deterministic-CBOR `SIV1` array.
    ///
    /// The unsigned fields are encoded once for the digest check and extended
    /// in place by the digest into the returned bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation or canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, FrontierArtifactErrorV1> {
        self.verified_unsigned()
            .map(|unsigned| signed_encoding(unsigned, self.invalidation_digest))
    }

    /// Validate the fields and return the unsigned encoding whose digest
    /// matches the declared `invalidation_digest`.
    fn verified_unsigned(&self) -> Result<Vec<u8>, FrontierArtifactErrorV1> {
        validate_invalidation_fields(self)
            .and_then(|()| {
                unsigned_encoding(
                    &invalidation_fields(self),
                    INVALIDATION_DIGEST_DOMAIN_V1,
                    MAX_SUFFIX_INVALIDATION_BYTES_V1,
                )
            })
            .and_then(|(digest, unsigned)| {
                matching_digest(digest, self.invalidation_digest).map(|()| unsigned)
            })
    }

    /// Decode and validate exact canonical `SIV1` bytes.
    ///
    /// The size bound is checked before decoding, and the only encoding after
    /// the canonical round-trip check is the one the digest needs.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for oversized, malformed, noncanonical, or
    /// invalid `SIV1` records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, FrontierArtifactErrorV1> {
        decode_bounded(bytes, INVALIDATION_LIMITS)
            .and_then(|value| {
                decode_invalidation(&value).map_err(|failure| contract_error(failure.error))
            })
            .and_then(|invalidation| {
                validate_invalidation_fields(&invalidation)
                    .and_then(|()| {
                        verify_record_digest(
                            &invalidation_fields(&invalidation),
                            invalidation.invalidation_digest,
                            INVALIDATION_DIGEST_DOMAIN_V1,
                        )
                    })
                    .map(|()| invalidation)
            })
    }

    /// Compute the `SIV1` domain-separated digest over fields 0 through 16.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error if the unsigned fields cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], FrontierArtifactErrorV1> {
        unsigned_digest(&invalidation_fields(self), INVALIDATION_DIGEST_DOMAIN_V1)
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

/// Build the exact six-field dependency-node coordinate through the shared
/// counterfactual node codec.
pub(crate) fn dependency_node_value(node: &DependencyNodeV1) -> Value {
    node_value(node)
}

/// Decode a six-field dependency-node coordinate through the shared
/// counterfactual node codec, naming the first malformed field.
pub(crate) fn decode_dependency_node_value(
    value: &Value,
) -> Result<DependencyNodeV1, &'static str> {
    decode_node(value).map_err(|failure| NODE_FIELD_NAMES[failure.slot])
}

/// Decode the `RCF1` array shape without validating bounds, order, or digest,
/// naming the first malformed field with its nested-evidence name.
pub(crate) fn decode_recomputation_frontier_value(
    value: &Value,
) -> Result<RecomputationFrontierV1, (FrontierArtifactErrorV1, &'static str)> {
    decode_frontier(value)
        .map_err(|failure| (contract_error(failure.error), frontier_field_name(failure)))
}

/// Decode the `SIV1` array shape without validating bounds, order, or digest,
/// naming the first malformed field with its nested-evidence name.
pub(crate) fn decode_suffix_invalidation_value(
    value: &Value,
) -> Result<SuffixInvalidationV1, (FrontierArtifactErrorV1, &'static str)> {
    decode_invalidation(value).map_err(|failure| {
        (
            contract_error(failure.error),
            invalidation_field_name(failure),
        )
    })
}

/// Nested-evidence name of the first malformed `RCF1` field; a malformed item
/// of a seed, affected-node, owner-frontier, or unknown-edge list is named by
/// its own field.
fn frontier_field_name(failure: FieldFailure) -> &'static str {
    let item_names: &[&'static str] = match failure.slot {
        FRONTIER_SEEDS_SLOT | FRONTIER_AFFECTED_SLOT => &NODE_FIELD_NAMES,
        FRONTIER_OWNERS_SLOT => &OWNER_FRONTIER_FIELD_NAMES,
        FRONTIER_UNKNOWN_EDGES_SLOT => &UNKNOWN_EDGE_FIELD_NAMES,
        _ => &[],
    };
    field_name(failure, &FRONTIER_FIELD_NAMES, item_names)
}

/// Nested-evidence name of the first malformed `SIV1` field; a malformed
/// invalid artifact is named by its own field.
fn invalidation_field_name(failure: FieldFailure) -> &'static str {
    let item_names: &[&'static str] = if failure.slot == INVALID_ARTIFACTS_SLOT {
        &INVALID_ARTIFACT_FIELD_NAMES
    } else {
        &[]
    };
    field_name(failure, &INVALIDATION_FIELD_NAMES, item_names)
}

/// The item field name when a list item failed, else the record field name.
fn field_name(
    failure: FieldFailure,
    field_names: &[&'static str],
    item_names: &[&'static str],
) -> &'static str {
    failure
        .item_slot
        .and_then(|slot| item_names.get(slot))
        .copied()
        .unwrap_or(field_names[failure.slot])
}

/// Read every `RCF1` field straight-line; a failure carries its reader slot.
fn decode_frontier(value: &Value) -> Result<RecomputationFrontierV1, FieldFailure> {
    let mut fields =
        FieldReader::with_header(value, FRONTIER_FIELDS, RECOMPUTATION_FRONTIER_MAGIC_V1, 1);
    let frontier = RecomputationFrontierV1 {
        frontier_id: fields.read_bytes(),
        plan_digest: fields.read_bytes(),
        parent_cut_digest: fields.read_bytes(),
        dependency_graph_digest: fields.read_bytes(),
        intervention_seed_nodes: fields.read_node_list(),
        affected_nodes: fields.read_node_list(),
        owner_frontiers: fields.read_record_array(owner_frontier_field),
        global_frontier_tick: fields.read_u64(),
        global_frontier_scheduler_position: fields.read_u32(),
        unknown_edge_policy: fields
            .read_enum(&UnknownEdgePolicyV1::ALL_V1, UnknownEdgePolicyV1::Reject),
        unknown_edge_coordinates: fields.read_record_array(unknown_edge_field),
        endogenous_suffix_end_tick: fields.read_u64(),
        classification_bundle_digest: fields.read_bytes(),
        provenance_digest: fields.read_bytes(),
        frontier_digest: fields.read_bytes(),
    };
    fields.finish_at().map(|()| frontier)
}

/// Read every `SIV1` field straight-line; a failure carries its reader slot.
fn decode_invalidation(value: &Value) -> Result<SuffixInvalidationV1, FieldFailure> {
    let mut fields =
        FieldReader::with_header(value, INVALIDATION_FIELDS, SUFFIX_INVALIDATION_MAGIC_V1, 1);
    let invalidation_id = fields.read_bytes();
    let plan_digest = fields.read_bytes();
    let fork_id = fields.read_bytes();
    let prior_generation = fields.read_u64();
    let new_generation = fields.read_u64();
    let frontier_digest = fields.read_bytes();
    let invalid_start = fields.read_node();
    let invalid_end = fields.read_node();
    let invalid_artifacts = fields.read_record_array(invalid_artifact_field);
    let invalid_checkpoint_digests = fields.read_bytes_list();
    let invalid_projection_digests = fields.read_bytes_list();
    let retained_exogenous_digests = fields.read_bytes_list();
    let reason = fields.read_enum(&REASONS, SuffixInvalidationReasonV1::NewIntervention);
    let (commit_timeline_id, commit_seq, commit_tick) = fields
        .read_nested(COMMIT_COORDINATE_FIELDS, |commit| {
            (commit.read_bytes(), commit.read_u64(), commit.read_u64())
        });
    let provenance_digest = fields.read_bytes();
    let invalidation_digest = fields.read_bytes();
    fields.finish_at().map(|()| SuffixInvalidationV1 {
        invalidation_id,
        plan_digest,
        fork_id,
        prior_generation,
        new_generation,
        frontier_digest,
        invalid_start,
        invalid_end,
        invalid_artifacts,
        invalid_checkpoint_digests,
        invalid_projection_digests,
        retained_exogenous_digests,
        reason,
        commit_timeline_id,
        commit_seq,
        commit_tick,
        provenance_digest,
        invalidation_digest,
    })
}

fn owner_frontier_field(value: &Value) -> Result<OwnerFrontierV1, FieldFailure> {
    let mut fields = FieldReader::new(value, OWNER_FRONTIER_FIELDS);
    let owner = OwnerFrontierV1 {
        owner_id: fields.read_text(),
        earliest_tick: fields.read_u64(),
        earliest_scheduler_position: fields.read_u32(),
        earliest_output_ordinal: fields.read_u32(),
        cause_node_digests: fields.read_bytes_list(),
    };
    fields.finish_at().map(|()| owner)
}

fn unknown_edge_field(value: &Value) -> Result<UnknownEdgeCoordinateV1, FieldFailure> {
    let mut fields = FieldReader::new(value, UNKNOWN_EDGE_FIELDS);
    let edge = UnknownEdgeCoordinateV1 {
        consumer: fields.read_node(),
        missing_source_digest: fields.read_optional_bytes(),
    };
    fields.finish_at().map(|()| edge)
}

fn invalid_artifact_field(value: &Value) -> Result<InvalidArtifactV1, FieldFailure> {
    let mut fields = FieldReader::new(value, INVALID_ARTIFACT_FIELDS);
    let artifact = InvalidArtifactV1 {
        artifact_class: fields.read_text(),
        schema_id: fields.read_u32(),
        artifact_digest: fields.read_bytes(),
        producer: fields.read_node(),
        prior_generation: fields.read_u64(),
        reason: fields.read_enum(&REASONS, SuffixInvalidationReasonV1::NewIntervention),
    };
    fields.finish_at().map(|()| artifact)
}

fn validate_frontier_fields(
    frontier: &RecomputationFrontierV1,
) -> Result<(), FrontierArtifactErrorV1> {
    if !frontier_counts_within_bounds(
        frontier.intervention_seed_nodes.len(),
        frontier.affected_nodes.len(),
        frontier.owner_frontiers.len(),
        frontier.unknown_edge_coordinates.len(),
    ) || !frontier_identifiers_nonzero(frontier)
        || !frontier
            .intervention_seed_nodes
            .iter()
            .all(DependencyNodeV1::is_valid_coordinate)
        || !frontier
            .affected_nodes
            .iter()
            .all(DependencyNodeV1::is_valid_coordinate)
        || !frontier.owner_frontiers.iter().all(valid_owner_frontier)
        || !frontier
            .unknown_edge_coordinates
            .iter()
            .all(valid_unknown_edge)
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
    if !invalidation_counts_within_bounds(
        invalidation.invalid_artifacts.len(),
        invalidation.invalid_checkpoint_digests.len(),
        invalidation.invalid_projection_digests.len(),
        invalidation.retained_exogenous_digests.len(),
    ) || !invalidation_identifiers_nonzero(invalidation)
        || !valid_coordinate(&invalidation.invalid_start)
        || !valid_coordinate(&invalidation.invalid_end)
        || !invalidation
            .invalid_artifacts
            .iter()
            .all(|artifact| valid_invalid_artifact(artifact, invalidation))
        || !invalidation.invalid_checkpoint_digests.iter().all(nonzero)
        || !invalidation.invalid_projection_digests.iter().all(nonzero)
        || !invalidation.retained_exogenous_digests.iter().all(nonzero)
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

/// Invalid artifacts order by the full producer node, as in the nested
/// verifier and the counterfactual coordinator, then by class and digest.
fn compare_invalid_artifacts(left: &InvalidArtifactV1, right: &InvalidArtifactV1) -> Ordering {
    (
        &left.producer,
        left.artifact_class.as_bytes(),
        left.artifact_digest,
    )
        .cmp(&(
            &right.producer,
            right.artifact_class.as_bytes(),
            right.artifact_digest,
        ))
}

/// The `RCF1` list counts, checked before any per-item rule or encoding.
const fn frontier_counts_within_bounds(
    seeds: usize,
    affected: usize,
    owners: usize,
    unknown_edges: usize,
) -> bool {
    counted(seeds, MAX_SEED_NODES)
        && counted(affected, MAX_AFFECTED_NODES)
        && counted(owners, MAX_OWNER_FRONTIERS)
        && unknown_edges <= MAX_UNKNOWN_EDGE_COORDINATES_V1
}

/// The `SIV1` list counts, checked before any per-item rule or encoding.
const fn invalidation_counts_within_bounds(
    artifacts: usize,
    checkpoints: usize,
    projections: usize,
    retained: usize,
) -> bool {
    artifacts <= MAX_INVALID_ARTIFACTS
        && checkpoints <= MAX_DIGEST_LIST
        && projections <= MAX_DIGEST_LIST
        && retained <= MAX_DIGEST_LIST
}

/// Identifiers and digests are never all zero, matching the nested verifier.
fn frontier_identifiers_nonzero(frontier: &RecomputationFrontierV1) -> bool {
    nonzero(&frontier.frontier_id)
        && [
            frontier.plan_digest,
            frontier.parent_cut_digest,
            frontier.dependency_graph_digest,
            frontier.classification_bundle_digest,
            frontier.provenance_digest,
        ]
        .iter()
        .all(nonzero)
}

/// Identifiers and digests, including the Fork ID, are never all zero.
fn invalidation_identifiers_nonzero(invalidation: &SuffixInvalidationV1) -> bool {
    nonzero(&invalidation.invalidation_id)
        && nonzero(&invalidation.fork_id)
        && nonzero(&invalidation.commit_timeline_id)
        && [
            invalidation.plan_digest,
            invalidation.frontier_digest,
            invalidation.provenance_digest,
        ]
        .iter()
        .all(nonzero)
}

/// Every bounded list or identifier here holds between one and `maximum` items.
const fn counted(length: usize, maximum: usize) -> bool {
    length != 0 && length <= maximum
}

/// A bare coordinate: a bounded owner identifier.
const fn valid_coordinate(node: &DependencyNodeV1) -> bool {
    counted(node.owner_id.len(), MAX_DEPENDENCY_OWNER_ID_BYTES_V1)
}

/// The consumer names a produced artifact, and an identified missing source
/// has a nonzero digest (an unidentified source is `None`).
fn valid_unknown_edge(edge: &UnknownEdgeCoordinateV1) -> bool {
    edge.consumer.is_valid_coordinate()
        && edge
            .missing_source_digest
            .is_none_or(|digest| nonzero(&digest))
}

fn valid_owner_frontier(owner: &OwnerFrontierV1) -> bool {
    counted(owner.owner_id.len(), MAX_DEPENDENCY_OWNER_ID_BYTES_V1)
        && counted(owner.cause_node_digests.len(), MAX_CAUSE_DIGESTS_V1)
        && owner.cause_node_digests.iter().all(nonzero)
}

/// An invalid artifact carries its producer's schema and the record's reason,
/// as in the nested verifier, and was produced in the record's prior
/// generation.
fn valid_invalid_artifact(
    artifact: &InvalidArtifactV1,
    invalidation: &SuffixInvalidationV1,
) -> bool {
    counted(artifact.artifact_class.len(), MAX_ARTIFACT_CLASS_BYTES)
        && nonzero(&artifact.artifact_digest)
        && artifact.producer.is_valid_coordinate()
        && artifact.schema_id == artifact.producer.schema_id
        && artifact.reason == invalidation.reason
        && artifact.prior_generation == invalidation.prior_generation
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
fn unsigned_digest(fields: &[Value], domain: &[u8]) -> Result<[u8; 32], FrontierArtifactErrorV1> {
    encode_value(&fields[..fields.len() - 1])
        .map(|unsigned| domain_digest(domain, &unsigned))
        .map_err(contract_error)
}

/// Compare the digest over `fields` with the record's declared digest.
fn verify_record_digest(
    fields: &[Value],
    declared: [u8; 32],
    domain: &[u8],
) -> Result<(), FrontierArtifactErrorV1> {
    unsigned_digest(fields, domain).and_then(|computed| matching_digest(computed, declared))
}

/// Encode the unsigned fields, every field but the trailing digest, once and
/// return their digest with that encoding, bounding the signed record size.
///
/// Both records hold fewer than 24 fields, so the signed and unsigned array
/// headers are each one byte and the signed record is exactly
/// [`DIGEST_FIELD_BYTES`] longer; its size is derived without encoding it.
/// The declared digest does not change that length, so a record awaiting its
/// digest is bounded exactly like the sealed one.
fn unsigned_encoding(
    fields: &[Value],
    domain: &[u8],
    maximum: usize,
) -> Result<([u8; 32], Vec<u8>), FrontierArtifactErrorV1> {
    encode_value(&fields[..fields.len() - 1])
        .map_err(contract_error)
        .and_then(|unsigned| {
            within_size(signed_length(unsigned.len()), maximum)
                .map(|()| (domain_digest(domain, &unsigned), unsigned))
        })
}

/// Encoded length of the signed record whose unsigned fields encode to
/// `unsigned` bytes.
const fn signed_length(unsigned: usize) -> usize {
    unsigned + DIGEST_FIELD_BYTES
}

/// Extend the unsigned encoding into the signed record: the one-byte array
/// header counts one more item, followed by the trailing `bstr(32)` digest.
fn signed_encoding(mut unsigned: Vec<u8>, digest: [u8; 32]) -> Vec<u8> {
    unsigned[0] += 1;
    unsigned.extend_from_slice(&[0x58, 0x20]);
    unsigned.extend_from_slice(&digest);
    unsigned
}

fn frontier_fields(frontier: &RecomputationFrontierV1) -> Vec<Value> {
    vec![
        text_value(RECOMPUTATION_FRONTIER_MAGIC_V1),
        uint_value(1),
        bytes_value(&frontier.frontier_id),
        bytes_value(&frontier.plan_digest),
        bytes_value(&frontier.parent_cut_digest),
        bytes_value(&frontier.dependency_graph_digest),
        node_list(&frontier.intervention_seed_nodes),
        node_list(&frontier.affected_nodes),
        Value::Array(
            frontier
                .owner_frontiers
                .iter()
                .map(owner_frontier_value)
                .collect(),
        ),
        uint_value(frontier.global_frontier_tick),
        uint_value(u64::from(frontier.global_frontier_scheduler_position)),
        uint_value(frontier.unknown_edge_policy.wire_code().into()),
        Value::Array(
            frontier
                .unknown_edge_coordinates
                .iter()
                .map(unknown_edge_value)
                .collect(),
        ),
        uint_value(frontier.endogenous_suffix_end_tick),
        bytes_value(&frontier.classification_bundle_digest),
        bytes_value(&frontier.provenance_digest),
        bytes_value(&frontier.frontier_digest),
    ]
}

fn invalidation_fields(invalidation: &SuffixInvalidationV1) -> Vec<Value> {
    vec![
        text_value(SUFFIX_INVALIDATION_MAGIC_V1),
        uint_value(1),
        bytes_value(&invalidation.invalidation_id),
        bytes_value(&invalidation.plan_digest),
        bytes_value(&invalidation.fork_id),
        uint_value(invalidation.prior_generation),
        uint_value(invalidation.new_generation),
        bytes_value(&invalidation.frontier_digest),
        node_value(&invalidation.invalid_start),
        node_value(&invalidation.invalid_end),
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
        uint_value(invalidation_reason_code(invalidation.reason)),
        Value::Array(vec![
            bytes_value(&invalidation.commit_timeline_id),
            uint_value(invalidation.commit_seq),
            uint_value(invalidation.commit_tick),
        ]),
        bytes_value(&invalidation.provenance_digest),
        bytes_value(&invalidation.invalidation_digest),
    ]
}

fn owner_frontier_value(owner: &OwnerFrontierV1) -> Value {
    Value::Array(vec![
        text_value(&owner.owner_id),
        uint_value(owner.earliest_tick),
        uint_value(u64::from(owner.earliest_scheduler_position)),
        uint_value(u64::from(owner.earliest_output_ordinal)),
        digest_list(&owner.cause_node_digests),
    ])
}

fn unknown_edge_value(edge: &UnknownEdgeCoordinateV1) -> Value {
    Value::Array(vec![
        node_value(&edge.consumer),
        edge.missing_source_digest
            .map_or(Value::Null, |digest| bytes_value(&digest)),
    ])
}

fn invalid_artifact_value(artifact: &InvalidArtifactV1) -> Value {
    Value::Array(vec![
        text_value(&artifact.artifact_class),
        uint_value(u64::from(artifact.schema_id)),
        bytes_value(&artifact.artifact_digest),
        node_value(&artifact.producer),
        uint_value(artifact.prior_generation),
        uint_value(invalidation_reason_code(artifact.reason)),
    ])
}

fn node_list(nodes: &[DependencyNodeV1]) -> Value {
    Value::Array(nodes.iter().map(node_value).collect())
}

fn digest_list(digests: &[[u8; 32]]) -> Value {
    Value::Array(
        digests
            .iter()
            .map(|digest| bytes_value(digest.as_slice()))
            .collect(),
    )
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

/// Bound the input before any parsing, then preflight nesting and list
/// lengths and require the exact canonical re-encoding.
fn decode_bounded(bytes: &[u8], limits: CborLimits) -> Result<Value, FrontierArtifactErrorV1> {
    within_size(bytes.len(), limits.maximum_bytes)
        .and_then(|()| decode_canonical(bytes, limits).map_err(contract_error))
}

/// One size rule serves both directions so encode and decode cannot disagree.
const fn within_size(length: usize, maximum: usize) -> Result<(), FrontierArtifactErrorV1> {
    if length > maximum {
        Err(FrontierArtifactErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

const fn contract_error(error: WireError) -> FrontierArtifactErrorV1 {
    match error {
        WireError::InvalidEncoding => FrontierArtifactErrorV1::InvalidEncoding,
        WireError::FieldOutOfBounds => FrontierArtifactErrorV1::FieldOutOfBounds,
        WireError::UnsupportedVersion => FrontierArtifactErrorV1::UnsupportedVersion,
        WireError::UnknownEnum => FrontierArtifactErrorV1::UnknownEnum,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod count_bound_tests {
    use super::*;

    #[test]
    fn list_limits_are_pinned() {
        assert_eq!(MAX_SEED_NODES, 1_024);
        assert_eq!(MAX_AFFECTED_NODES, 1_000_000);
        assert_eq!(MAX_OWNER_FRONTIERS, 4_096);
        assert_eq!(MAX_UNKNOWN_EDGE_COORDINATES_V1, 65_536);
        assert_eq!(MAX_CAUSE_DIGESTS_V1, 4_096);
        assert_eq!(MAX_INVALID_ARTIFACTS, 1_000_000);
        assert_eq!(MAX_DIGEST_LIST, 65_536);
    }

    /// The signed record is the unsigned encoding plus the 34-byte digest
    /// field, so its size is bounded without a second full encoding.
    #[test]
    fn signed_size_and_bytes_extend_the_unsigned_encoding() {
        let fields = [text_value("RCF1"), uint_value(1), bytes_value(&[7; 32])];
        let full = encode_value(&fields).unwrap_or_default();
        let (_, unsigned) = unsigned_encoding(&fields, b"domain", full.len()).unwrap_or_default();
        assert_eq!(signed_length(unsigned.len()), full.len());
        assert_eq!(signed_encoding(unsigned, [7; 32]), full);
        assert_eq!(
            unsigned_encoding(&fields, b"domain", full.len() - 1).map(drop),
            Err(FrontierArtifactErrorV1::FieldOutOfBounds)
        );
        let maximum = MAX_RECOMPUTATION_FRONTIER_BYTES_V1;
        assert_eq!(
            within_size(signed_length(maximum - DIGEST_FIELD_BYTES), maximum),
            Ok(())
        );
        assert_eq!(
            within_size(signed_length(maximum - DIGEST_FIELD_BYTES + 1), maximum),
            Err(FrontierArtifactErrorV1::FieldOutOfBounds)
        );
    }

    #[test]
    fn named_list_slots_match_their_field_names() {
        assert_eq!(FRONTIER_FIELD_NAMES[FRONTIER_SEEDS_SLOT], "frontier_seeds");
        assert_eq!(
            FRONTIER_FIELD_NAMES[FRONTIER_AFFECTED_SLOT],
            "frontier_affected"
        );
        assert_eq!(
            FRONTIER_FIELD_NAMES[FRONTIER_OWNERS_SLOT],
            "frontier_owners"
        );
        assert_eq!(
            FRONTIER_FIELD_NAMES[FRONTIER_UNKNOWN_EDGES_SLOT],
            "frontier_unknown_edges"
        );
        assert_eq!(
            INVALIDATION_FIELD_NAMES[INVALID_ARTIFACTS_SLOT],
            "invalid_artifacts"
        );
    }

    /// The million-entry limits are checked on counts alone, so they are
    /// exercised here without allocating a million-entry record.
    #[test]
    fn frontier_counts_accept_each_limit_and_reject_one_more() {
        let limits = [
            MAX_SEED_NODES,
            MAX_AFFECTED_NODES,
            MAX_OWNER_FRONTIERS,
            MAX_UNKNOWN_EDGE_COORDINATES_V1,
        ];
        assert!(frontier_counts_within_bounds(
            limits[0], limits[1], limits[2], limits[3]
        ));
        assert!(frontier_counts_within_bounds(1, 1, 1, 0));
        for (index, limit) in limits.into_iter().enumerate() {
            let mut over = [1, 1, 1, 0];
            over[index] = limit + 1;
            assert!(!frontier_counts_within_bounds(
                over[0], over[1], over[2], over[3]
            ));
        }
        for index in [0, 1, 2] {
            let mut empty = [1, 1, 1, 0];
            empty[index] = 0;
            assert!(!frontier_counts_within_bounds(
                empty[0], empty[1], empty[2], empty[3]
            ));
        }
    }

    #[test]
    fn invalidation_counts_accept_each_limit_and_reject_one_more() {
        let limits = [
            MAX_INVALID_ARTIFACTS,
            MAX_DIGEST_LIST,
            MAX_DIGEST_LIST,
            MAX_DIGEST_LIST,
        ];
        assert!(invalidation_counts_within_bounds(
            limits[0], limits[1], limits[2], limits[3]
        ));
        assert!(invalidation_counts_within_bounds(0, 0, 0, 0));
        for (index, limit) in limits.into_iter().enumerate() {
            let mut over = [0; 4];
            over[index] = limit + 1;
            assert!(!invalidation_counts_within_bounds(
                over[0], over[1], over[2], over[3]
            ));
        }
    }
}
