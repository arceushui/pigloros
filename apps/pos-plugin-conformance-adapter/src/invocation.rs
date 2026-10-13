//! The invocation source and the Plugin of the conformance Drivers (ADR-061 revision 8
//! decision 2).
//!
//! [`FixtureInvocationSourceV1`] implements `InvocationContextSourceV1`. It builds the full
//! `PluginInvocationV1` and `HostInputs` of a `pass` from the inputs the port stores for the
//! step: the invocation ID, the random domain, the byte offset of the keyed-BLAKE3 stream
//! (`timeline_position.seq`), the observation bytes and the simulation time. The artifact
//! references, the output base ordinal, the scheduler position, the provenance root and the
//! budget ID are fixed constants. `tick`, the trust policy snapshot digest and the execution
//! profile digest are copied from the Driver's binding (ADR-061 revision 7 decision 8). The
//! prior state is the Driver's own committed state, which the Driver substitutes on every pass.

use std::sync::{Arc, Mutex, PoisonError};

use pos_core::{Capability, Kind, Plugin, PluginId, TimelineId};
use pos_plugin_supervisor::{
    InvocationBindingV1, InvocationContextSourceV1, InvocationContextV1,
};
use pos_runtime::community_plugin_host::{
    ArtifactRefV1, CommunityPluginHostErrorV1, HostInputs, PluginInvocationV1, TimelinePositionV1,
};
use pos_runtime::ObservationView;

/// The deterministic budget ID of every invocation.
pub const BUDGET_ID: &str = "conformance";

/// The provenance root of every invocation: 32 bytes of `0x05`.
const PROVENANCE_ROOT: [u8; 32] = [5; 32];

/// The inputs of the next `pass` step.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PassInputsV1 {
    pub invocation_id: [u8; 16],
    pub random_domain: [u8; 32],
    /// The byte offset into the random stream.
    pub timeline_seq: u64,
    pub observation: Vec<u8>,
    pub simulation_time: u64,
}

/// The inputs the port writes and the Driver's source reads.
pub type SharedInputsV1 = Arc<Mutex<PassInputsV1>>;

/// A reference to an empty artifact with schema ID `schema_id` and a zero digest.
const fn artifact(schema_id: u32) -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id,
        byte_length: 0,
        digest: [0; 32],
    }
}

/// The context of one invocation: `inputs`, the constants, and `binding` copied in.
///
/// A missing profile digest is written as zeros, which the supervisor refuses.
#[must_use]
pub fn build_context(
    inputs: PassInputsV1,
    timeline: TimelineId,
    binding: InvocationBindingV1,
) -> InvocationContextV1 {
    InvocationContextV1 {
        invocation: PluginInvocationV1 {
            invocation_id: inputs.invocation_id,
            timeline_position: TimelinePositionV1 {
                timeline_id: timeline.inner().to_bytes(),
                seq: inputs.timeline_seq,
                tick: binding.tick,
                scheduler_position: 0,
            },
            output_base_ordinal: 0,
            principal_ref: artifact(1),
            authorization_decision: artifact(2),
            observation_snapshot: artifact(3),
            observation_bytes: inputs.observation,
            prior_state_schema: [0; 32],
            prior_state_bytes: Vec::new(),
            execution_profile_digest: binding.execution_profile_digest.unwrap_or([0; 32]),
            trust_policy_snapshot_digest: binding.tps1_digest,
            deterministic_budget_id: BUDGET_ID.to_owned(),
            deterministic_random_domain: inputs.random_domain,
            provenance_root: PROVENANCE_ROOT,
        },
        host_inputs: HostInputs {
            simulation_time: inputs.simulation_time,
        },
    }
}

/// The invocation source of one conformance Driver.
#[derive(Clone, Debug)]
pub struct FixtureInvocationSourceV1 {
    inputs: SharedInputsV1,
}

impl FixtureInvocationSourceV1 {
    /// A source that reads the inputs the port writes to `inputs`.
    #[must_use]
    pub const fn new(inputs: SharedInputsV1) -> Self {
        Self { inputs }
    }
}

impl InvocationContextSourceV1 for FixtureInvocationSourceV1 {
    fn context(
        &mut self,
        timeline: TimelineId,
        _observation: &ObservationView<'_>,
        binding: InvocationBindingV1,
    ) -> Result<InvocationContextV1, CommunityPluginHostErrorV1> {
        let inputs = self
            .inputs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Ok(build_context(inputs, timeline, binding))
    }
}

/// The Plugin a conformance Driver is registered as: it owns the Event type of its `bind` step.
#[derive(Clone, Debug)]
pub struct ConformancePluginV1 {
    id: PluginId,
    event_type: String,
}

impl ConformancePluginV1 {
    /// A fresh Plugin that owns `event_type`.
    #[must_use]
    pub fn new(event_type: &str) -> Self {
        Self {
            id: PluginId::new(),
            event_type: event_type.to_owned(),
        }
    }
}

impl Plugin for ConformancePluginV1 {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "conformance"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.event_type.as_str())],
            has_driver: true,
            ..Capability::default()
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
