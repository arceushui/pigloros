//! Host types for the `contract-v1` records that cross the Component boundary.
//!
//! The host builds a [`PluginInvocationV1`] and receives a validated
//! [`PluginOutputV1`], [`PluginDescriptorV1`] or [`GuestPluginErrorV1`]. Fixed
//! lengths are part of the types: every `digest32` is `[u8; 32]`, and every
//! `invocation-id`, `timeline-id` and `entity-id` is `[u8; 16]`.

use pos_crypto::plugin_execution::is_valid_id_v1;
use pos_runtime::community_plugin_host::CommunityPluginHostErrorV1;
use wasmtime::component::Val;

use crate::host_v1::byte_list;

/// WIT bound on observation bytes, in bytes (1 MiB).
pub const MAX_OBSERVATION_BYTES_V1: usize = 1_048_576;
/// WIT bound on prior and next state bytes, in bytes (1 MiB).
pub const MAX_STATE_BYTES_V1: usize = 1_048_576;

/// `contract-v1.artifact-ref`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactRefV1 {
    /// Registered schema ID.
    pub schema_id: u32,
    /// Exact artifact length.
    pub byte_length: u64,
    /// BLAKE3-256 artifact digest.
    pub digest: [u8; 32],
}

/// `contract-v1.timeline-position`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimelinePositionV1 {
    /// Timeline ID.
    pub timeline_id: [u8; 16],
    /// Timeline sequence number.
    pub seq: u64,
    /// Tick.
    pub tick: u64,
    /// Scheduler position inside the Tick.
    pub scheduler_position: u32,
}

/// `contract-v1.plugin-invocation`, without its `kind`.
///
/// The engine sets `kind` from the export it invokes, so an invocation can
/// never name the other export. The host verifies every referenced artifact
/// and digest before it builds one (ADR-061); the engine checks the bounds
/// WIT cannot express before any guest code runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginInvocationV1 {
    /// Invocation ID.
    pub invocation_id: [u8; 16],
    /// Timeline position of the invocation.
    pub timeline_position: TimelinePositionV1,
    /// First output ordinal of this invocation.
    pub output_base_ordinal: u32,
    /// Principal reference.
    pub principal_ref: ArtifactRefV1,
    /// Authorization decision reference.
    pub authorization_decision: ArtifactRefV1,
    /// `ObservationSnapshot` reference.
    pub observation_snapshot: ArtifactRefV1,
    /// Observation bytes, at most 1 MiB.
    pub observation_bytes: Vec<u8>,
    /// Prior state schema digest.
    pub prior_state_schema: [u8; 32],
    /// Prior state bytes, at most 1 MiB.
    pub prior_state_bytes: Vec<u8>,
    /// Execution profile digest.
    pub execution_profile_digest: [u8; 32],
    /// Trust policy snapshot digest.
    pub trust_policy_snapshot_digest: [u8; 32],
    /// Deterministic budget ID, an ADR-061 ID.
    pub deterministic_budget_id: String,
    /// Deterministic random domain.
    pub deterministic_random_domain: [u8; 32],
    /// Provenance root.
    pub provenance_root: [u8; 32],
}

impl PluginInvocationV1 {
    /// Check the bounds WIT cannot express.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInvocation` when the observation or the prior state
    /// exceeds 1 MiB, or the budget ID is not an ADR-061 ID.
    pub fn validate(&self) -> Result<(), CommunityPluginHostErrorV1> {
        let valid = self.observation_bytes.len() <= MAX_OBSERVATION_BYTES_V1
            && self.prior_state_bytes.len() <= MAX_STATE_BYTES_V1
            && is_valid_id_v1(&self.deterministic_budget_id);
        valid
            .then_some(())
            .ok_or(CommunityPluginHostErrorV1::InvalidInvocation)
    }

    /// The Canonical ABI value of this invocation with `kind`.
    pub(crate) fn to_val(&self, kind: &str) -> Val {
        record(vec![
            ("invocation-id", byte_list(&self.invocation_id)),
            ("kind", Val::Enum(kind.to_owned())),
            (
                "timeline-position",
                record(vec![
                    ("timeline-id", byte_list(&self.timeline_position.timeline_id)),
                    ("seq", Val::U64(self.timeline_position.seq)),
                    ("tick", Val::U64(self.timeline_position.tick)),
                    (
                        "scheduler-position",
                        Val::U32(self.timeline_position.scheduler_position),
                    ),
                ]),
            ),
            ("output-base-ordinal", Val::U32(self.output_base_ordinal)),
            ("principal-ref", artifact(&self.principal_ref)),
            ("authorization-decision", artifact(&self.authorization_decision)),
            ("observation-snapshot", artifact(&self.observation_snapshot)),
            ("observation-bytes", byte_list(&self.observation_bytes)),
            ("prior-state-schema", digest(&self.prior_state_schema)),
            ("prior-state-bytes", byte_list(&self.prior_state_bytes)),
            (
                "execution-profile-digest",
                digest(&self.execution_profile_digest),
            ),
            (
                "trust-policy-snapshot-digest",
                digest(&self.trust_policy_snapshot_digest),
            ),
            (
                "deterministic-budget-id",
                record(vec![(
                    "utf8",
                    byte_list(self.deterministic_budget_id.as_bytes()),
                )]),
            ),
            (
                "deterministic-random-domain",
                digest(&self.deterministic_random_domain),
            ),
            ("provenance-root", digest(&self.provenance_root)),
        ])
    }
}

fn record(fields: Vec<(&str, Val)>) -> Val {
    Val::Record(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn digest(value: &[u8; 32]) -> Val {
    record(vec![("value", byte_list(value))])
}

fn artifact(value: &ArtifactRefV1) -> Val {
    record(vec![
        ("schema-id", Val::U32(value.schema_id)),
        ("byte-length", Val::U64(value.byte_length)),
        ("digest", digest(&value.digest)),
    ])
}

/// `contract-v1.event-draft`, validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDraftV1 {
    /// Event schema ID.
    pub event_schema_id: u32,
    /// Entity ID.
    pub entity_id: [u8; 16],
    /// Event type, an ADR-061 ID.
    pub event_type: String,
    /// Canonical payload bytes.
    pub canonical_payload: Vec<u8>,
    /// Dependency digests, strictly increasing.
    pub dependency_digests: Vec<[u8; 32]>,
}

/// `contract-v1.trace-annotation`, validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceAnnotationV1 {
    /// Annotation schema ID.
    pub annotation_schema_id: u32,
    /// Canonical annotation bytes.
    pub canonical_bytes: Vec<u8>,
    /// Dependency digests, strictly increasing.
    pub dependency_digests: Vec<[u8; 32]>,
}

/// `contract-v1.plugin-output`, fully validated against its invocation.
///
/// Nothing in it is committed by the engine: the supervisor approves and
/// commits it as one value at the Tick Boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginOutputV1 {
    /// The invocation's ID, echoed.
    pub invocation_id: [u8; 16],
    /// `EventDrafts`, in the guest's order.
    pub event_drafts: Vec<EventDraftV1>,
    /// Next state schema digest.
    pub next_state_schema: [u8; 32],
    /// Next state bytes.
    pub next_state_bytes: Vec<u8>,
    /// Trace annotations, in the guest's order.
    pub trace_annotations: Vec<TraceAnnotationV1>,
    /// Consumed dependency digests, strictly increasing.
    pub consumed_dependencies: Vec<[u8; 32]>,
    /// The output digest, equal to [`crate::digest::plugin_output_digest_v1`].
    pub output_digest: [u8; 32],
}

/// `contract-v1.plugin-descriptor`, checked against the negotiated release.
///
/// `capabilities` and `dependencies` are checked against their count bounds
/// only, and `migrations` must be empty, so none of them is kept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginDescriptorV1 {
    /// Plugin ID, equal to the negotiated PMF1 Plugin ID.
    pub plugin_id: String,
    /// Release semver text, 1-64 bytes.
    pub release_semver: String,
    /// World, equal to the negotiated world.
    pub world: String,
    /// ABI major, equal to the negotiated major.
    pub abi_major: u16,
    /// Lowest ABI minor, equal to the PMF1 declaration.
    pub min_abi_minor: u16,
    /// Highest ABI minor, equal to the PMF1 declaration.
    pub max_abi_minor: u16,
    /// Required features, equal to the negotiated ones.
    pub required_features: Vec<String>,
    /// Event schema digests, strictly increasing.
    pub event_schema_digests: Vec<[u8; 32]>,
    /// State schema digest.
    pub state_schema_digest: [u8; 32],
    /// The guest's declared manifest digest.
    pub manifest_digest: [u8; 32],
    /// The guest's declared release digest.
    pub release_digest: [u8; 32],
}

/// `contract-v1.field-ref`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldRefV1 {
    /// Schema ID.
    pub schema_id: u32,
    /// Field ordinal.
    pub field_ordinal: u16,
}

/// `contract-v1.plugin-error-code`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginErrorCodeV1 {
    /// `invalid-invocation`.
    InvalidInvocation(FieldRefV1),
    /// `unsupported-schema`.
    UnsupportedSchema(u32),
    /// `capability-required`, with an ADR-061 capability ID.
    CapabilityRequired(String),
    /// `dependency-missing`.
    DependencyMissing([u8; 32]),
    /// `deterministic-budget-exhausted`.
    DeterministicBudgetExhausted,
    /// `invalid-state`.
    InvalidState(FieldRefV1),
    /// `migration-rejected`.
    MigrationRejected(FieldRefV1),
    /// `guest-declared-failure`.
    GuestDeclaredFailure(u16),
}

/// `contract-v1.plugin-error`: the guest's own typed failure, validated.
///
/// ADR-061 records the exact variant, ordinal, coordinate and digest as the
/// outcome. No `EventDraft` or state accompanies it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestPluginErrorV1 {
    /// The error code.
    pub code: PluginErrorCodeV1,
    /// Canonical coordinate, at most 128 bytes.
    pub canonical_coordinate: Option<Vec<u8>>,
    /// Related digest.
    pub related_digest: Option<[u8; 32]>,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const ARTIFACT: ArtifactRefV1 = ArtifactRefV1 {
        schema_id: 1,
        byte_length: 0,
        digest: [0; 32],
    };

    fn invocation() -> PluginInvocationV1 {
        PluginInvocationV1 {
            invocation_id: [1; 16],
            timeline_position: TimelinePositionV1 {
                timeline_id: [2; 16],
                seq: 3,
                tick: 4,
                scheduler_position: 5,
            },
            output_base_ordinal: 6,
            principal_ref: ARTIFACT,
            authorization_decision: ARTIFACT,
            observation_snapshot: ARTIFACT,
            observation_bytes: vec![0; MAX_OBSERVATION_BYTES_V1],
            prior_state_schema: [7; 32],
            prior_state_bytes: vec![0; MAX_STATE_BYTES_V1],
            execution_profile_digest: [8; 32],
            trust_policy_snapshot_digest: [9; 32],
            deterministic_budget_id: "budget".to_owned(),
            deterministic_random_domain: [10; 32],
            provenance_root: [11; 32],
        }
    }

    #[test]
    fn invocations_stay_within_the_wit_bounds() {
        let error = Err(CommunityPluginHostErrorV1::InvalidInvocation);
        assert_eq!(invocation().validate(), Ok(()));
        let mut large = invocation();
        large.observation_bytes.push(0);
        assert_eq!(large.validate(), error);
        let mut large = invocation();
        large.prior_state_bytes.push(0);
        assert_eq!(large.validate(), error);
        let mut unnamed = invocation();
        unnamed.deterministic_budget_id = "Budget".to_owned();
        assert_eq!(unnamed.validate(), error);
    }

    #[test]
    fn invocations_lower_in_wit_field_order() {
        let Val::Record(fields) = invocation().to_val("drive") else {
            std::panic::resume_unwind(Box::new("not a record"));
        };
        let names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "invocation-id",
                "kind",
                "timeline-position",
                "output-base-ordinal",
                "principal-ref",
                "authorization-decision",
                "observation-snapshot",
                "observation-bytes",
                "prior-state-schema",
                "prior-state-bytes",
                "execution-profile-digest",
                "trust-policy-snapshot-digest",
                "deterministic-budget-id",
                "deterministic-random-domain",
                "provenance-root",
            ]
        );
        assert_eq!(fields[1].1, Val::Enum("drive".to_owned()));
        assert_eq!(fields[3].1, Val::U32(6));
    }
}
