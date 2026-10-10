//! The community Plugin Component host contract (ADR-061 revision 4).
//!
//! This module holds what the host fixes before any worker exists: the
//! closed host error surface, the host-owned execution profile for each live
//! Execution Mode, the negotiation of one validated PMF1 V1 release against
//! them, and the guest contract types that cross the Component boundary. It
//! loads, launches and executes nothing, and links no WebAssembly runtime.

mod contract;
mod error;
mod failure;
mod negotiation;
mod profile;

pub use contract::{
    plugin_output_digest_v1, ArtifactRefV1, EventDraftV1, FieldRefV1, GuestPluginErrorV1,
    GuestReturnV1, HostInputs, InvocationOptionsV1, InvocationReportV1, MeteringV1,
    OperationalLogRecord, PluginDescriptorV1, PluginErrorCodeV1, PluginInvocationV1,
    PluginOutputV1, TimelinePositionV1, TraceAnnotationV1, MAX_OBSERVATION_BYTES_V1,
    MAX_STATE_BYTES_V1, MAX_TRACE_ANNOTATION_BYTES_V1, PLUGIN_OUTPUT_DIGEST_DOMAIN_V1,
};
pub use error::{
    AtomicCommitFailureV1, CommunityPluginHostErrorV1, ComponentTrapClassV1, HostFailureClassV1,
    RevocationBasisV1, TrapReproductionV1, TrustDenialBasisV1,
};
pub use failure::{classify_pass_failure, quarantine_for, PassFailureV1};
pub use negotiation::{
    negotiate_community_plugin_v1, CommunityPluginHostAbiErrorV1, CommunityPluginHostAbiV1,
    EffectiveExecutionLimitsV1, NegotiatedCommunityPluginV1, NegotiatedTransportErrorV1,
    NegotiatedTransportV1, COMMUNITY_PLUGIN_ABI_MAJOR_V1,
};
pub use profile::{
    CeilingValuesV1, CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1,
    CommunityPluginModeV1, CommunityPluginProfileErrorV1, ExecutionLimitV1,
    PinnedComponentRuntimeV1, PinnedEngineConfigV1, TrapOutcomeV1, TrapTableEntryV1,
};
