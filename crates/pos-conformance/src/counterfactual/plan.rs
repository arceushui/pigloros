//! Immutable CFP1 counterfactual plans defined by ADR-064.
//!
//! A `CounterfactualPlanV1` is the complete, digest-sealed request that the
//! core `CounterfactualCoordinator` admits before it invalidates and
//! recomputes one Fork suffix. The record binds the plan, room, and parent
//! cut; the first recomputed Tick and the inclusive horizon; the ordered INT1
//! Interventions; the frozen `ExogenousFrozen` and `FixedPolicy` descriptors;
//! the classification bundle and the unknown-edge policy; the EPF1
//! execution-profile and TPS1 trust-policy identities; the Plugin
//! composition, scheduler, numeric, budget, and failure-policy identities; the
//! requested `ReplayClaim`; and the previous plan digest. This module owns
//! only the strict codec, the domain-separated digest, and structural
//! validation; admission, authorization, consent, graph traversal,
//! transactions, execution, and result generation belong to the coordinator.
//!
//! Contract decisions that ADR-064 leaves open:
//!
//! - The exact wire form is a 26-field deterministic-CBOR array in
//!   [`CounterfactualPlanV1`] declaration order, preceded by the `CFP1` magic
//!   and version `1`: `[magic, version, plan_id, room_id, room_digest,
//!   parent_timeline_id, parent_cut_seq, parent_cut_tick, parent_cut_digest,
//!   first_tick, horizon_tick, interventions, exogenous_descriptors,
//!   fixed_policy_descriptors, classification_bundle_digest,
//!   unknown_edge_policy, execution_profile, trust_policy,
//!   plugin_composition_digest, scheduler_digest, numeric_profile_digest,
//!   budget_digest, failure_policy_digest, replay_claim, previous_plan_digest,
//!   plan_digest]`. The plan digest covers fields 0 through 24 under the
//!   `PiglorOS.CounterfactualPlan.v1\0` domain.
//! - The unknown-edge policy is bound next to the classification bundle, so
//!   a missing dependency edge is handled as the plan requested. It uses the
//!   `RCF1` wire codes of [`UnknownEdgePolicyV1::ALL_V1`].
//! - Each Intervention travels as its exact canonical INT1 bytes in a CBOR
//!   byte string, so INT1 remains the single owner of its codec and its
//!   closed errors surface unchanged through
//!   [`CounterfactualPlanContractErrorV1::Intervention`]. The ordered list
//!   holds 1 through 1,024 Interventions (an empty list is rejected) and is
//!   validated by [`validate_plan_interventions_v1`].
//! - The first recomputed Tick is exactly the Tick after the parent cut, and
//!   every Intervention is effective inside `first_tick..=horizon_tick`. An
//!   earlier effective Tick is `InterventionBeforeCut`; a later one is out of
//!   bounds.
//! - `ExogenousFrozen` and `FixedPolicy` descriptors share one shape,
//!   `[schema_id, artifact_digest, authorization_digest, provenance_digest]`.
//!   Each list is strictly ordered by `(schema_id, artifact_digest)`, which
//!   is the ADR artifact order `(class, schema, digest)` within one class, and
//!   one `(schema_id, artifact_digest)` identity may not be classified in both
//!   lists. Either list may be empty.
//! - The EPF1 identity is `[profile_id, semantic_version, profile_digest]` and
//!   the TPS1 identity is `[policy_id, epoch, snapshot_digest]`; both are
//!   built from validated records by their `from_*` constructors. The Plugin
//!   composition, scheduler, numeric profile, deterministic budgets, and
//!   failure policy are bound by opaque 32-byte digests whose records are
//!   owned elsewhere.
//! - The requested `ReplayClaim` uses the CFR1 wire codes 0 through 4 and any
//!   claim may be requested; whether evidence supports it is decided later.
//! - A plan cannot supersede itself: `previous_plan_digest` must differ from
//!   `plan_digest`.
//! - The plan ID, the parent timeline ID, and the room, parent-cut,
//!   classification-bundle, EPF1 profile, TPS1 snapshot, Plugin composition,
//!   scheduler, numeric-profile, budget, failure-policy, and any previous-plan
//!   digests are nonzero, and every descriptor names a nonzero schema with
//!   nonzero digests; an all-zero placeholder is out of bounds.
//! - The plan carries no operational path: every artifact is a digest, and
//!   the room, profile, and policy identifiers are 1 through 128 bytes of
//!   UTF-8 without control characters that neither start with `/`, `~`, or a
//!   drive-letter prefix such as `C:`, contain `\`, nor contain a `.` or `..`
//!   path component.
//! - The deterministic-CBOR nesting depth is at most 3, counting the record
//!   array as depth 0: the deepest legal items are the scalar fields of a
//!   descriptor, inside a descriptor array (depth 2) inside a descriptor list
//!   (depth 1). INT1 Interventions are opaque byte strings at depth 2.
//!
//! The largest structurally valid record encodes to about 12.5 MB (1,024
//! Interventions of at most about 4.9 KB, 65,536 exogenous and 4,096
//! `FixedPolicy` descriptors of 108 bytes, plus fixed fields), below the 16 MiB
//! bound, which is therefore enforced on untrusted input before allocation.

use super::codec::{
    bytes_value, decode_canonical, encode_value, nonzero, text_value, uint_value, CborLimits,
    FieldReader, WireError,
};
use super::intervention::{
    validate_plan_interventions_v1, InterventionContractErrorV1, InterventionV1,
};
use super::replay_claim::{replay_claim_code, REPLAY_CLAIMS};
use crate::{
    domain_digest, ExecutionProfileContractErrorV1, ExecutionProfileV1, ReplayClaimV1,
    TrustPolicySnapshotContractErrorV1, TrustPolicySnapshotV1, UnknownEdgePolicyV1,
};
use ciborium::value::Value;
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Magic for the immutable counterfactual-plan record.
pub const COUNTERFACTUAL_PLAN_MAGIC_V1: &str = "CFP1";
/// Maximum encoded size of a CFP1 counterfactual plan.
pub const MAX_COUNTERFACTUAL_PLAN_BYTES_V1: usize = 16 * 1024 * 1024;
/// Maximum number of `ExogenousFrozen` descriptors bound by one plan.
pub const MAX_EXOGENOUS_DESCRIPTORS_PER_PLAN_V1: usize = 65_536;
/// Maximum number of `FixedPolicy` descriptors bound by one plan.
pub const MAX_FIXED_POLICY_DESCRIPTORS_PER_PLAN_V1: usize = 4_096;

const FIELD_COUNT: usize = 26;
const DESCRIPTOR_FIELD_COUNT: usize = 4;
const EXECUTION_PROFILE_REF_FIELD_COUNT: usize = 3;
const TRUST_POLICY_REF_FIELD_COUNT: usize = 3;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_SEMANTIC_VERSION_BYTES: usize = 64;
const LIMITS: CborLimits = CborLimits {
    maximum_bytes: MAX_COUNTERFACTUAL_PLAN_BYTES_V1,
    // Deepest legal item: a descriptor field (record 0, list 1, descriptor 2,
    // field 3).
    maximum_depth: 3,
    maximum_items: 65_536,
    allow_simple_values: true,
};
const PLAN_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.CounterfactualPlan.v1";

/// Closed safe errors exposed by the CFP1 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterfactualPlanContractErrorV1 {
    /// The bytes are malformed, noncanonical, or contain a forbidden CBOR type.
    InvalidEncoding,
    /// The record magic or schema version is not supported.
    UnsupportedVersion,
    /// A value, list, range, identifier, or encoded record exceeds its bound.
    FieldOutOfBounds,
    /// A closed enum code is not defined by CFP1 version 1.
    UnknownEnum,
    /// A descriptor list is not strictly ordered by `(schema_id, artifact_digest)`.
    NonCanonicalOrder,
    /// A descriptor identity repeats within or across the descriptor lists.
    DuplicateIdentity,
    /// An Intervention is effective before the first Tick after the parent cut.
    InterventionBeforeCut,
    /// An embedded INT1 record or the ordered Intervention list is invalid.
    Intervention(InterventionContractErrorV1),
    /// The content does not match its declared plan digest.
    DigestMismatch,
}

impl std::fmt::Display for CounterfactualPlanContractErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid CFP1 counterfactual plan encoding",
            Self::UnsupportedVersion => "unsupported CFP1 counterfactual plan version",
            Self::FieldOutOfBounds => "CFP1 counterfactual plan field is out of bounds",
            Self::UnknownEnum => "CFP1 counterfactual plan enum code is unknown",
            Self::NonCanonicalOrder => "CFP1 counterfactual plan descriptors are not canonical",
            Self::DuplicateIdentity => "CFP1 counterfactual plan descriptor is duplicated",
            Self::InterventionBeforeCut => {
                "CFP1 counterfactual plan intervention is effective before the cut"
            }
            Self::Intervention(_) => "CFP1 counterfactual plan intervention is invalid",
            Self::DigestMismatch => "CFP1 counterfactual plan digest does not match",
        })
    }
}

impl std::error::Error for CounterfactualPlanContractErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Intervention(error) => Some(error),
            _ => None,
        }
    }
}

/// One digest-identified frozen input bound by a plan.
///
/// The same shape describes an `ExogenousFrozen` input and a `FixedPolicy`
/// identity; the list that holds it names its class. The CFP1 wire form is
/// `[schema_id, artifact_digest, authorization_digest, provenance_digest]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenArtifactDescriptorV1 {
    /// Schema ID of the frozen artifact.
    pub schema_id: u32,
    /// Exact digest of the frozen artifact bytes that may be reused.
    pub artifact_digest: [u8; 32],
    /// Digest of the consent, capability, and trust authorization for reuse.
    pub authorization_digest: [u8; 32],
    /// Digest of the artifact's provenance record.
    pub provenance_digest: [u8; 32],
}

/// The EPF1 execution-profile identity bound by a plan.
///
/// The CFP1 wire form is `[profile_id, semantic_version, profile_digest]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanExecutionProfileRefV1 {
    /// EPF1 profile identifier.
    pub profile_id: String,
    /// EPF1 profile semantic version.
    pub semantic_version: String,
    /// EPF1 profile digest.
    pub profile_digest: [u8; 32],
}

impl PlanExecutionProfileRefV1 {
    /// Bind the identity of one validated EPF1 execution profile.
    ///
    /// # Errors
    ///
    /// Returns the EPF1 error when the profile is invalid.
    pub fn from_execution_profile_v1(
        profile: &ExecutionProfileV1,
    ) -> Result<Self, ExecutionProfileContractErrorV1> {
        profile.validate().map(|()| Self {
            profile_id: profile.profile_id.clone(),
            semantic_version: profile.semantic_version.clone(),
            profile_digest: profile.profile_digest,
        })
    }
}

/// The TPS1 trust-policy snapshot identity bound by a plan.
///
/// The CFP1 wire form is `[policy_id, epoch, snapshot_digest]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanTrustPolicyRefV1 {
    /// TPS1 policy identifier.
    pub policy_id: String,
    /// TPS1 policy epoch; it starts at 1.
    pub epoch: u64,
    /// TPS1 content digest of the complete signed snapshot.
    pub snapshot_digest: [u8; 32],
}

impl PlanTrustPolicyRefV1 {
    /// Bind the identity of one validated TPS1 trust-policy snapshot.
    ///
    /// # Errors
    ///
    /// Returns the TPS1 error when the snapshot is invalid.
    pub fn from_trust_policy_snapshot_v1(
        snapshot: &TrustPolicySnapshotV1,
    ) -> Result<Self, TrustPolicySnapshotContractErrorV1> {
        snapshot.digest().map(|snapshot_digest| Self {
            policy_id: snapshot.policy_id.clone(),
            epoch: snapshot.epoch,
            snapshot_digest,
        })
    }
}

/// Complete immutable counterfactual plan represented by a CFP1 record.
///
/// The exact deterministic-CBOR array has 26 fields: magic `CFP1`, version
/// `1`, then the fields below in declaration order. The plan digest covers
/// fields 0 through 24 under the `PiglorOS.CounterfactualPlan.v1\0` domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterfactualPlanV1 {
    /// Plan identifier.
    pub plan_id: [u8; 16],
    /// Scenario Room identifier.
    pub room_id: String,
    /// Digest of the Scenario Room closure.
    pub room_digest: [u8; 32],
    /// Timeline identifier of the parent whose prefix is inherited.
    pub parent_timeline_id: [u8; 16],
    /// Parent logical-head sequence number at the cut.
    pub parent_cut_seq: u64,
    /// Last parent Tick inherited through the cut.
    pub parent_cut_tick: u64,
    /// Digest of the parent cut.
    pub parent_cut_digest: [u8; 32],
    /// First recomputed Tick; exactly the Tick after the parent cut.
    pub first_tick: u64,
    /// Inclusive horizon Tick; not before the first Tick.
    pub horizon_tick: u64,
    /// 1 to 1,024 Interventions ordered by `(effective_tick, ordinal, id)`;
    /// an empty list is rejected.
    pub interventions: Vec<InterventionV1>,
    /// Up to 65,536 strictly ordered `ExogenousFrozen` descriptors.
    pub exogenous_descriptors: Vec<FrozenArtifactDescriptorV1>,
    /// Up to 4,096 strictly ordered `FixedPolicy` descriptors.
    pub fixed_policy_descriptors: Vec<FrozenArtifactDescriptorV1>,
    /// Digest of the dependency-classification bundle.
    pub classification_bundle_digest: [u8; 32],
    /// How recomputation treats a required dependency edge that the graph
    /// cannot resolve.
    pub unknown_edge_policy: UnknownEdgePolicyV1,
    /// EPF1 execution-profile identity.
    pub execution_profile: PlanExecutionProfileRefV1,
    /// TPS1 trust-policy snapshot identity.
    pub trust_policy: PlanTrustPolicyRefV1,
    /// Digest of the pinned Plugin composition.
    pub plugin_composition_digest: [u8; 32],
    /// Digest of the pinned scheduler and Driver order.
    pub scheduler_digest: [u8; 32],
    /// Digest of the pinned numeric profile.
    pub numeric_profile_digest: [u8; 32],
    /// Digest of the deterministic budgets.
    pub budget_digest: [u8; 32],
    /// Digest of the failure policy.
    pub failure_policy_digest: [u8; 32],
    /// Replay claim requested for the recomputed suffix.
    pub replay_claim: ReplayClaimV1,
    /// Digest of the plan this plan supersedes, if any; never `plan_digest`.
    pub previous_plan_digest: Option<[u8; 32]>,
    /// Domain-separated digest over fields 0 through 24.
    pub plan_digest: [u8; 32],
}

impl CounterfactualPlanV1 {
    /// Validate CFP1 bounds, identifiers, the ordered Interventions and their
    /// effective window, descriptor order and uniqueness, and the plan digest.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field, ordering, or digest is invalid.
    pub fn validate(&self) -> Result<(), CounterfactualPlanContractErrorV1> {
        validated_body_fields(self).map(drop)
    }

    /// Encode this plan as an exact deterministic-CBOR CFP1 array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, CounterfactualPlanContractErrorV1> {
        validated_body_fields(self).and_then(|mut fields| {
            fields.push(bytes_value(&self.plan_digest));
            encode_value(&fields).map_err(contract_error)
        })
    }

    /// Decode and validate exact canonical CFP1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, oversized, or
    /// structurally invalid CFP1 records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, CounterfactualPlanContractErrorV1> {
        decode_canonical(bytes, LIMITS)
            .map_err(contract_error)
            .and_then(|value| decode_plan(&value))
            .and_then(|plan| plan.validate().map(|()| plan))
    }

    /// Compute the CFP1 domain-separated digest over fields 0 through 24.
    ///
    /// The digest is computed over the fields as they are, without validating
    /// the plan, so a caller can seal a plan before validating it.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when an embedded Intervention cannot be
    /// encoded as canonical INT1.
    pub fn digest(&self) -> Result<[u8; 32], CounterfactualPlanContractErrorV1> {
        digested_body_fields(self).map(|(_, digest)| digest)
    }
}

/// Validate every CFP1 rule and return the unsigned body fields 0 through 24,
/// so encoding reuses the field list that the digest check already built.
fn validated_body_fields(
    plan: &CounterfactualPlanV1,
) -> Result<Vec<Value>, CounterfactualPlanContractErrorV1> {
    validate_bounds(plan)
        .and_then(|()| {
            validate_plan_interventions_v1(&plan.interventions)
                .map_err(CounterfactualPlanContractErrorV1::Intervention)
        })
        .and_then(|()| validate_intervention_window(plan))
        .and_then(|()| validate_descriptors(plan))
        .and_then(|()| digested_body_fields(plan))
        .and_then(|(fields, digest)| {
            if digest == plan.plan_digest {
                Ok(fields)
            } else {
                Err(CounterfactualPlanContractErrorV1::DigestMismatch)
            }
        })
}

/// Build the unsigned body fields 0 through 24 once and digest their
/// deterministic-CBOR array encoding under the CFP1 domain.
fn digested_body_fields(
    plan: &CounterfactualPlanV1,
) -> Result<(Vec<Value>, [u8; 32]), CounterfactualPlanContractErrorV1> {
    body_fields(plan).and_then(|fields| {
        encode_value(&fields)
            .map_err(contract_error)
            .map(|unsigned| {
                let digest = domain_digest(PLAN_DIGEST_DOMAIN_V1, &unsigned);
                (fields, digest)
            })
    })
}

fn validate_bounds(plan: &CounterfactualPlanV1) -> Result<(), CounterfactualPlanContractErrorV1> {
    if valid_identities(plan)
        && nonzero_digests(plan)
        && valid_tick_range(plan)
        && valid_descriptor_counts(plan)
        && plan
            .exogenous_descriptors
            .iter()
            .chain(&plan.fixed_policy_descriptors)
            .all(valid_descriptor)
        && plan.previous_plan_digest != Some(plan.plan_digest)
    {
        Ok(())
    } else {
        Err(CounterfactualPlanContractErrorV1::FieldOutOfBounds)
    }
}

/// Whether the room, EPF1, and TPS1 identities are within their bounds.
fn valid_identities(plan: &CounterfactualPlanV1) -> bool {
    plan_identifier(&plan.room_id)
        && plan_identifier(&plan.execution_profile.profile_id)
        && crate::semantic_version(
            &plan.execution_profile.semantic_version,
            MAX_SEMANTIC_VERSION_BYTES,
            None,
        )
        && plan_identifier(&plan.trust_policy.policy_id)
        && plan.trust_policy.epoch != 0
}

/// Whether every plan, timeline, cut, room, classification, EPF1, TPS1,
/// Plugin, and previous-plan identity is nonzero.
fn nonzero_digests(plan: &CounterfactualPlanV1) -> bool {
    nonzero(&plan.plan_id)
        && nonzero(&plan.parent_timeline_id)
        && [
            plan.room_digest,
            plan.parent_cut_digest,
            plan.classification_bundle_digest,
            plan.execution_profile.profile_digest,
            plan.trust_policy.snapshot_digest,
            plan.plugin_composition_digest,
            plan.scheduler_digest,
            plan.numeric_profile_digest,
            plan.budget_digest,
            plan.failure_policy_digest,
        ]
        .iter()
        .all(nonzero)
        && plan
            .previous_plan_digest
            .is_none_or(|digest| nonzero(&digest))
}

/// Whether a descriptor names a schema and carries nonzero digests.
fn valid_descriptor(descriptor: &FrozenArtifactDescriptorV1) -> bool {
    descriptor.schema_id != 0
        && nonzero(&descriptor.artifact_digest)
        && nonzero(&descriptor.authorization_digest)
        && nonzero(&descriptor.provenance_digest)
}

/// Whether the first Tick directly follows the cut and precedes the horizon.
fn valid_tick_range(plan: &CounterfactualPlanV1) -> bool {
    plan.parent_cut_tick.checked_add(1) == Some(plan.first_tick)
        && plan.first_tick <= plan.horizon_tick
}

/// Whether each descriptor list is within its class bound.
const fn valid_descriptor_counts(plan: &CounterfactualPlanV1) -> bool {
    plan.exogenous_descriptors.len() <= MAX_EXOGENOUS_DESCRIPTORS_PER_PLAN_V1
        && plan.fixed_policy_descriptors.len() <= MAX_FIXED_POLICY_DESCRIPTORS_PER_PLAN_V1
}

/// Whether an identifier is bounded UTF-8 text that is not an operational path.
fn plan_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
        && !value.starts_with(['/', '~'])
        && !has_drive_letter_prefix(value)
        && !value.contains('\\')
        && !value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

/// Whether a value starts with a drive-letter prefix such as `C:`.
const fn has_drive_letter_prefix(value: &str) -> bool {
    matches!(value.as_bytes(), [letter, b':', ..] if letter.is_ascii_alphabetic())
}

fn validate_intervention_window(
    plan: &CounterfactualPlanV1,
) -> Result<(), CounterfactualPlanContractErrorV1> {
    if plan
        .interventions
        .iter()
        .any(|intervention| intervention.effective_tick < plan.first_tick)
    {
        Err(CounterfactualPlanContractErrorV1::InterventionBeforeCut)
    } else if plan
        .interventions
        .iter()
        .any(|intervention| intervention.effective_tick > plan.horizon_tick)
    {
        Err(CounterfactualPlanContractErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_descriptors(
    plan: &CounterfactualPlanV1,
) -> Result<(), CounterfactualPlanContractErrorV1> {
    validate_descriptor_order(&plan.exogenous_descriptors)
        .and_then(|()| validate_descriptor_order(&plan.fixed_policy_descriptors))
        .and_then(|()| {
            let exogenous = plan
                .exogenous_descriptors
                .iter()
                .map(descriptor_key)
                .collect::<BTreeSet<_>>();
            if plan
                .fixed_policy_descriptors
                .iter()
                .any(|descriptor| exogenous.contains(&descriptor_key(descriptor)))
            {
                Err(CounterfactualPlanContractErrorV1::DuplicateIdentity)
            } else {
                Ok(())
            }
        })
}

fn validate_descriptor_order(
    descriptors: &[FrozenArtifactDescriptorV1],
) -> Result<(), CounterfactualPlanContractErrorV1> {
    descriptors.windows(2).try_for_each(|pair| {
        match descriptor_key(&pair[0]).cmp(&descriptor_key(&pair[1])) {
            Ordering::Less => Ok(()),
            Ordering::Equal => Err(CounterfactualPlanContractErrorV1::DuplicateIdentity),
            Ordering::Greater => Err(CounterfactualPlanContractErrorV1::NonCanonicalOrder),
        }
    })
}

const fn descriptor_key(descriptor: &FrozenArtifactDescriptorV1) -> (u32, [u8; 32]) {
    (descriptor.schema_id, descriptor.artifact_digest)
}

fn body_fields(
    plan: &CounterfactualPlanV1,
) -> Result<Vec<Value>, CounterfactualPlanContractErrorV1> {
    plan.interventions
        .iter()
        .map(|intervention| intervention.to_canonical_cbor().map(Value::Bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(CounterfactualPlanContractErrorV1::Intervention)
        .map(|interventions| {
            vec![
                text_value(COUNTERFACTUAL_PLAN_MAGIC_V1),
                uint_value(1),
                bytes_value(&plan.plan_id),
                text_value(&plan.room_id),
                bytes_value(&plan.room_digest),
                bytes_value(&plan.parent_timeline_id),
                uint_value(plan.parent_cut_seq),
                uint_value(plan.parent_cut_tick),
                bytes_value(&plan.parent_cut_digest),
                uint_value(plan.first_tick),
                uint_value(plan.horizon_tick),
                Value::Array(interventions),
                encode_descriptors(&plan.exogenous_descriptors),
                encode_descriptors(&plan.fixed_policy_descriptors),
                bytes_value(&plan.classification_bundle_digest),
                uint_value(plan.unknown_edge_policy.wire_code().into()),
                encode_execution_profile_ref(&plan.execution_profile),
                encode_trust_policy_ref(&plan.trust_policy),
                bytes_value(&plan.plugin_composition_digest),
                bytes_value(&plan.scheduler_digest),
                bytes_value(&plan.numeric_profile_digest),
                bytes_value(&plan.budget_digest),
                bytes_value(&plan.failure_policy_digest),
                uint_value(replay_claim_code(plan.replay_claim)),
                plan.previous_plan_digest
                    .map_or(Value::Null, |digest| bytes_value(&digest)),
            ]
        })
}

fn encode_descriptors(descriptors: &[FrozenArtifactDescriptorV1]) -> Value {
    Value::Array(
        descriptors
            .iter()
            .map(|descriptor| {
                Value::Array(vec![
                    uint_value(descriptor.schema_id.into()),
                    bytes_value(&descriptor.artifact_digest),
                    bytes_value(&descriptor.authorization_digest),
                    bytes_value(&descriptor.provenance_digest),
                ])
            })
            .collect(),
    )
}

fn encode_execution_profile_ref(profile: &PlanExecutionProfileRefV1) -> Value {
    Value::Array(vec![
        text_value(&profile.profile_id),
        text_value(&profile.semantic_version),
        bytes_value(&profile.profile_digest),
    ])
}

fn encode_trust_policy_ref(policy: &PlanTrustPolicyRefV1) -> Value {
    Value::Array(vec![
        text_value(&policy.policy_id),
        uint_value(policy.epoch),
        bytes_value(&policy.snapshot_digest),
    ])
}

/// Read every field straight-line through one reader, then decode the
/// embedded INT1 records, whose closed errors surface unchanged.
fn decode_plan(value: &Value) -> Result<CounterfactualPlanV1, CounterfactualPlanContractErrorV1> {
    let mut fields = FieldReader::with_header(value, FIELD_COUNT, COUNTERFACTUAL_PLAN_MAGIC_V1, 1);
    let plan_id = fields.read_bytes();
    let room_id = fields.read_text();
    let room_digest = fields.read_bytes();
    let parent_timeline_id = fields.read_bytes();
    let parent_cut_seq = fields.read_u64();
    let parent_cut_tick = fields.read_u64();
    let parent_cut_digest = fields.read_bytes();
    let first_tick = fields.read_u64();
    let horizon_tick = fields.read_u64();
    let interventions = fields.read_byte_string_list();
    let exogenous_descriptors = fields.read_array(descriptor_field);
    let fixed_policy_descriptors = fields.read_array(descriptor_field);
    let classification_bundle_digest = fields.read_bytes();
    let unknown_edge_policy =
        fields.read_enum(&UnknownEdgePolicyV1::ALL_V1, UnknownEdgePolicyV1::Reject);
    let execution_profile = fields.read_nested(EXECUTION_PROFILE_REF_FIELD_COUNT, |profile| {
        PlanExecutionProfileRefV1 {
            profile_id: profile.read_text(),
            semantic_version: profile.read_text(),
            profile_digest: profile.read_bytes(),
        }
    });
    let trust_policy = fields.read_nested(TRUST_POLICY_REF_FIELD_COUNT, |policy| {
        PlanTrustPolicyRefV1 {
            policy_id: policy.read_text(),
            epoch: policy.read_u64(),
            snapshot_digest: policy.read_bytes(),
        }
    });
    let plugin_composition_digest = fields.read_bytes();
    let scheduler_digest = fields.read_bytes();
    let numeric_profile_digest = fields.read_bytes();
    let budget_digest = fields.read_bytes();
    let failure_policy_digest = fields.read_bytes();
    let replay_claim = fields.read_enum(&REPLAY_CLAIMS, ReplayClaimV1::Exact);
    let previous_plan_digest = fields.read_optional_bytes();
    let plan_digest = fields.read_bytes();
    fields
        .finish()
        .map_err(contract_error)
        .and_then(|()| {
            interventions
                .iter()
                .map(Vec::as_slice)
                .map(InterventionV1::from_canonical_cbor)
                .collect::<Result<Vec<_>, _>>()
                .map_err(CounterfactualPlanContractErrorV1::Intervention)
        })
        .map(|interventions| CounterfactualPlanV1 {
            plan_id,
            room_id,
            room_digest,
            parent_timeline_id,
            parent_cut_seq,
            parent_cut_tick,
            parent_cut_digest,
            first_tick,
            horizon_tick,
            interventions,
            exogenous_descriptors,
            fixed_policy_descriptors,
            classification_bundle_digest,
            unknown_edge_policy,
            execution_profile,
            trust_policy,
            plugin_composition_digest,
            scheduler_digest,
            numeric_profile_digest,
            budget_digest,
            failure_policy_digest,
            replay_claim,
            previous_plan_digest,
            plan_digest,
        })
}

fn descriptor_field(value: &Value) -> Result<FrozenArtifactDescriptorV1, WireError> {
    let mut fields = FieldReader::new(value, DESCRIPTOR_FIELD_COUNT);
    let descriptor = FrozenArtifactDescriptorV1 {
        schema_id: fields.read_u32(),
        artifact_digest: fields.read_bytes(),
        authorization_digest: fields.read_bytes(),
        provenance_digest: fields.read_bytes(),
    };
    fields.finish().map(|()| descriptor)
}

const fn contract_error(error: WireError) -> CounterfactualPlanContractErrorV1 {
    match error {
        WireError::InvalidEncoding => CounterfactualPlanContractErrorV1::InvalidEncoding,
        WireError::FieldOutOfBounds => CounterfactualPlanContractErrorV1::FieldOutOfBounds,
        WireError::UnsupportedVersion => CounterfactualPlanContractErrorV1::UnsupportedVersion,
        WireError::UnknownEnum => CounterfactualPlanContractErrorV1::UnknownEnum,
    }
}
