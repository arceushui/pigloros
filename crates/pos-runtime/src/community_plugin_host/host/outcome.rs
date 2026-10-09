//! What one host pass reports (ADR-061 revision 7 decision 10).

use pos_core::{PipelineCommitReceiptV1, PluginId};
use pos_plugin_release::ContentValidationV1;

use crate::community_plugin_host::{CommunityPluginHostErrorV1, GatedCommunityReleaseV1};
use crate::RuntimeError;

/// What the gate established about one member's release in this pass.
#[derive(Debug)]
pub struct GateSummaryV1 {
    /// The exact PMF1 Plugin ID text of the gated release.
    pub plugin_id: String,
    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    pub pmf1_digest: [u8; 32],
    /// The PMF1 release digest.
    pub release_digest: [u8; 32],
    /// The digest of the authenticated TPS1 the registry retained.
    pub tps1_digest: [u8; 32],
    /// The Tick of the pass.
    pub tick: u64,
    /// What was checked about the release content.
    pub content_validation: ContentValidationV1,
}

impl GateSummaryV1 {
    /// The summary of `gated`, which holds the Component bytes and so is dropped by the caller.
    pub(super) fn of(gated: &GatedCommunityReleaseV1) -> Self {
        Self {
            plugin_id: gated.plugin_id().to_owned(),
            pmf1_digest: gated.pmf1_digest(),
            release_digest: gated.release_digest(),
            tps1_digest: gated.tps1_digest(),
            tick: gated.tick(),
            content_validation: gated.content_validation(),
        }
    }
}

/// One selected member's entry of a pass.
#[derive(Debug)]
pub struct MemberPassV1 {
    /// The member's Plugin.
    pub plugin: PluginId,
    /// The PMF1 Plugin ID text the composition expected for the member.
    pub expected_plugin_id: String,
    /// The gate's summary, or the closed error that refused the member (or, after an offer
    /// failure, the `InvalidInvocation` that refused the pass).
    pub gate: Result<GateSummaryV1, CommunityPluginHostErrorV1>,
    /// The invocation ID the Driver built in this pass, if it got that far.
    pub invocation_id: Option<[u8; 16]>,
    /// The failure this pass produced for the member, never an earlier pass's.
    pub launch_failure: Option<CommunityPluginHostErrorV1>,
    /// The result of mirroring the member's availability into the registry after the pass.
    pub sync: Result<(), RuntimeError>,
}

/// The result of a pass as a whole.
#[derive(Debug)]
pub enum PassResultV1 {
    /// The sample or a member's gate or offer was refused: nothing was staged.
    Refused,
    /// The whole batch committed, with the commit receipt when the pass had any Event.
    Committed(Option<Box<PipelineCommitReceiptV1>>),
    /// The pass failed and was discarded. An outcome in doubt is `InDoubt`, never a failure.
    Failed {
        /// The closed host error that discarded the pass, or `None` when the error is the
        /// host's own and not a community Plugin host failure.
        host: Option<CommunityPluginHostErrorV1>,
        /// The registry's own error.
        error: Box<RuntimeError>,
    },
    /// The store outcome is unknown: the registry retains the staged state for
    /// `recover_scheduled_pass`.
    InDoubt,
}

/// The outcome of one `run_pass`.
#[derive(Debug)]
pub struct CommunityPassOutcomeV1 {
    /// The Tick of the pass.
    pub tick: u64,
    /// The trusted UTC second sampled for the pass, `None` when the sample failed.
    pub utc: Option<i64>,
    /// One entry per selected member, in host schedule order.
    pub gates: Vec<MemberPassV1>,
    /// How the pass ended.
    pub result: PassResultV1,
}
