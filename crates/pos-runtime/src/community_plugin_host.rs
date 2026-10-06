//! The community Plugin Component host contract (ADR-061 revision 4).
//!
//! This module holds what the host fixes before any worker exists: the
//! closed host error surface, the host-owned execution profile for each live
//! Execution Mode, and the negotiation of one validated PMF1 V1 release
//! against them. It loads, launches and executes nothing.

mod error;
mod negotiation;
mod profile;

pub use error::{
    AtomicCommitFailureV1, CommunityPluginHostErrorV1, ComponentTrapClassV1, HostFailureClassV1,
    TrapReproductionV1,
};
pub use negotiation::{
    negotiate_community_plugin_v1, CommunityPluginHostAbiErrorV1, CommunityPluginHostAbiV1,
    EffectiveExecutionLimitsV1, NegotiatedCommunityPluginV1, COMMUNITY_PLUGIN_ABI_MAJOR_V1,
};
pub use profile::{
    CeilingValuesV1, CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1,
    CommunityPluginModeV1, CommunityPluginProfileErrorV1, ExecutionLimitV1,
    PinnedComponentRuntimeV1, PinnedEngineConfigV1, TrapOutcomeV1, TrapTableEntryV1,
};
