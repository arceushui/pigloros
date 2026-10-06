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
};
pub use negotiation::{
    negotiate_community_plugin_v1, CommunityPluginHostAbiV1, EffectiveExecutionLimitsV1,
    NegotiatedCommunityPluginV1, COMMUNITY_PLUGIN_ABI_MAJOR_V1, WIT_EVENT_COUNT_CEILING_V1,
    WIT_LOG_CALLS_CEILING_V1, WIT_LOG_MESSAGE_BYTES_CEILING_V1, WIT_STATE_BYTES_CEILING_V1,
};
pub use profile::{
    CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1, CommunityPluginModeV1,
    CommunityPluginProfileErrorV1, ExecutionLimitV1, PinnedComponentRuntimeV1, TrapOutcomeV1,
    TrapTableEntryV1, WASM_PAGE_BYTES_V1,
};
